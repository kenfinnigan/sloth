package openslo

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"time"

	openslov1 "github.com/OpenSLO/oslo/pkg/manifest/v1"
	openslov1alpha "github.com/OpenSLO/oslo/pkg/manifest/v1alpha"
	"gopkg.in/yaml.v2"

	prometheusmodel "github.com/prometheus/common/model"
	"github.com/slok/sloth/internal/prometheus"
)

type YAMLSpecLoader struct {
	windowPeriod time.Duration
}

// YAMLSpecLoader knows how to load YAML specs and converts them to a model.
func NewYAMLSpecLoader(windowPeriod time.Duration) YAMLSpecLoader {
	return YAMLSpecLoader{
		windowPeriod: windowPeriod,
	}
}

var (
	specTypeV1AlphaRegexKind       = regexp.MustCompile(`(?m)^kind: +['"]?SLO['"]? *$`)
	specTypeV1AlphaRegexAPIVersion = regexp.MustCompile(`(?m)^apiVersion: +['"]?openslo\/v1alpha['"]? *$`)
	specTypeV1RegexKind            = regexp.MustCompile(`(?m)^kind: +['"]?SLO['"]? *$`)
	specTypeV1RegexAPIVersion      = regexp.MustCompile(`(?m)^apiVersion: +['"]?openslo\/v1['"]? *$`)
)

func (y YAMLSpecLoader) IsSpecType(ctx context.Context, data []byte) bool {
	return (specTypeV1AlphaRegexKind.Match(data) && specTypeV1AlphaRegexAPIVersion.Match(data)) ||
		(specTypeV1RegexKind.Match(data) && specTypeV1RegexAPIVersion.Match(data))
}

func (y YAMLSpecLoader) LoadSpec(ctx context.Context, data []byte) (*prometheus.SLOGroup, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("spec is required")
	}

	s := openslov1.SLO{}
	err := yaml.Unmarshal(data, &s)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshall YAML spec correctly: %w", err)
	}
	if s.APIVersion == openslov1alpha.APIVersion {
		s := openslov1alpha.SLO{}
		err := yaml.Unmarshal(data, &s)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshall YAML spec correctly: %w", err)
		}
		return y.validateV1AlphaSpec(ctx, s)
	}
	return y.validateV1Spec(ctx, s)
}

func (y YAMLSpecLoader) validateV1AlphaSpec(ctx context.Context, s openslov1alpha.SLO) (*prometheus.SLOGroup, error) {
	// Check version.
	if s.APIVersion != openslov1alpha.APIVersion {
		return nil, fmt.Errorf("invalid spec version, should be %q", openslov1alpha.APIVersion)
	}

	// Check at least we have one SLO.
	if len(s.Spec.Objectives) == 0 {
		return nil, fmt.Errorf("at least one SLO is required")
	}

	// Validate time windows are correct.
	err := y.validateV1AlphaTimeWindow(s)
	if err != nil {
		return nil, fmt.Errorf("invalid SLO time windows: %w", err)
	}

	m, err := y.mapV1AlphaSpecToModel(s)
	if err != nil {
		return nil, fmt.Errorf("could not map to model: %w", err)
	}

	return m, nil
}

func (y YAMLSpecLoader) validateV1Spec(ctx context.Context, s openslov1.SLO) (*prometheus.SLOGroup, error) {
	// Check version.
	if s.APIVersion != openslov1.APIVersion {
		return nil, fmt.Errorf("invalid spec version, should be %q", openslov1.APIVersion)
	}

	// Check at least we have one SLO.
	if len(s.Spec.Objectives) == 0 {
		return nil, fmt.Errorf("at least one SLO is required")
	}

	// Validate time windows are correct.
	err := y.validateV1TimeWindow(s)
	if err != nil {
		return nil, fmt.Errorf("invalid SLO time windows: %w", err)
	}

	m, err := y.mapV1SpecToModel(s)
	if err != nil {
		return nil, fmt.Errorf("could not map to model: %w", err)
	}

	return m, nil
}

func (y YAMLSpecLoader) mapV1AlphaSpecToModel(spec openslov1alpha.SLO) (*prometheus.SLOGroup, error) {
	slos, err := y.getV1AlphaSLOs(spec)
	if err != nil {
		return nil, fmt.Errorf("could not map SLOs correctly: %w", err)
	}

	return &prometheus.SLOGroup{SLOs: slos}, nil
}

func (y YAMLSpecLoader) mapV1SpecToModel(spec openslov1.SLO) (*prometheus.SLOGroup, error) {
	slos, err := y.getV1SLOs(spec)
	if err != nil {
		return nil, fmt.Errorf("could not map SLOs correctly: %w", err)
	}

	return &prometheus.SLOGroup{SLOs: slos}, nil
}

// validateV1AlphaTimeWindow will validate that Sloth only supports 30 day based time windows
// we need this because time windows are a required by OpenSLO.
func (YAMLSpecLoader) validateV1AlphaTimeWindow(spec openslov1alpha.SLO) error {
	if len(spec.Spec.TimeWindows) == 0 {
		return nil
	}

	if len(spec.Spec.TimeWindows) > 1 {
		return fmt.Errorf("only 1 time window is supported")
	}

	t := spec.Spec.TimeWindows[0]
	if strings.ToLower(t.Unit) != "day" {
		return fmt.Errorf("only days based time windows are supported")
	}

	return nil
}

// validateV1TimeWindow will validate that Sloth only supports 30 day based time windows
// we need this because time windows are a required by OpenSLO.
func (YAMLSpecLoader) validateV1TimeWindow(spec openslov1.SLO) error {
	if len(spec.Spec.TimeWindow) == 0 {
		return nil
	}

	if len(spec.Spec.TimeWindow) > 1 {
		return fmt.Errorf("only 1 time window is supported")
	}

	t := spec.Spec.TimeWindow[0]
	if !strings.HasSuffix(strings.ToLower(t.Duration), "d") {
		return fmt.Errorf("only days based time windows are supported")
	}

	return nil
}

var errorRatioRawQueryTpl = template.Must(template.New("").Parse(`
  1 - (
    (
      {{ .good }}
    )
    /
    (
      {{ .total }}
    )
  )
`))

// getV1AlphaSLI gets the SLI from the OpenSLO slo objective, we only support ratio based openSLO objectives,
// however we will convert to a raw based sloth SLI because the ratio queries that we have differ from
// Sloth. Sloth uses bad/total events, OpenSLO uses good/total events. We get the ratio using good events
// and then rest to 1, to get a raw error ratio query.
func (y YAMLSpecLoader) getV1AlphaSLI(spec openslov1alpha.SLOSpec, slo openslov1alpha.Objective) (*prometheus.SLI, error) {
	if slo.RatioMetrics == nil {
		return nil, fmt.Errorf("missing ratioMetrics")
	}

	good := slo.RatioMetrics.Good
	total := slo.RatioMetrics.Total

	if good.Source != "prometheus" && good.Source != "sloth" {
		return nil, fmt.Errorf("prometheus or sloth query ratio 'good' source is required")
	}

	if total.Source != "prometheus" && good.Source != "sloth" {
		return nil, fmt.Errorf("prometheus or sloth query ratio 'total' source is required")
	}

	if good.QueryType != "promql" {
		return nil, fmt.Errorf("unsupported 'good' indicator query type: %s", good.QueryType)
	}

	if total.QueryType != "promql" {
		return nil, fmt.Errorf("unsupported 'total' indicator query type: %s", total.QueryType)
	}

	// Map as good and total events as a raw query.
	var b bytes.Buffer
	err := errorRatioRawQueryTpl.Execute(&b, map[string]string{"good": good.Query, "total": total.Query})
	if err != nil {
		return nil, fmt.Errorf("could not execute mapping SLI template: %w", err)
	}

	return &prometheus.SLI{Raw: &prometheus.SLIRaw{
		ErrorRatioQuery: b.String(),
	}}, nil
}

// getV1AlphaSLOs will try getting all the objectives as individual SLOs, this way we can map
// to what Sloth understands as an SLO, that OpenSLO understands as a list of objectives
// for the same SLO.
func (y YAMLSpecLoader) getV1AlphaSLOs(spec openslov1alpha.SLO) ([]prometheus.SLO, error) {
	res := []prometheus.SLO{}

	for idx, slo := range spec.Spec.Objectives {
		sli, err := y.getV1AlphaSLI(spec.Spec, slo)
		if err != nil {
			return nil, fmt.Errorf("could not map SLI: %w", err)
		}

		timeWindow := y.windowPeriod
		if len(spec.Spec.TimeWindows) > 0 {
			timeWindow = time.Duration(spec.Spec.TimeWindows[0].Count) * 24 * time.Hour
		}

		// TODO(slok): Think about using `slo.Value` insted of idx (`slo.Value` is not mandatory).
		res = append(res, prometheus.SLO{
			ID:              fmt.Sprintf("%s-%s-%d", spec.Spec.Service, spec.Metadata.Name, idx),
			Name:            fmt.Sprintf("%s-%d", spec.Metadata.Name, idx),
			Service:         spec.Spec.Service,
			Description:     spec.Spec.Description,
			TimeWindow:      timeWindow,
			SLI:             *sli,
			Objective:       *slo.BudgetTarget * 100, // OpenSLO uses ratios, we use percents.
			PageAlertMeta:   prometheus.AlertMeta{Disable: true},
			TicketAlertMeta: prometheus.AlertMeta{Disable: true},
		})
	}

	return res, nil
}

// getV1BetaSLI gets the SLI from the OpenSLO slo objective, we only support ratio based openSLO objectives,
// however we will convert to a raw based sloth SLI because the ratio queries that we have differ from
// Sloth. Sloth uses bad/total events, OpenSLO uses good/total events. We get the ratio using good events
// and then rest to 1, to get a raw error ratio query.
func (y YAMLSpecLoader) getV1SLI(spec openslov1.SLOSpec, sli openslov1.SLISpec) (*prometheus.SLI, error) {
	if &sli.RatioMetric == nil {
		return nil, fmt.Errorf("missing ratioMetrics")
	}

	total := sli.RatioMetric.Total.MetricSource

	if &sli.RatioMetric.Good.MetricSource == nil && &sli.RatioMetric.Bad.MetricSource == nil {
		return nil, fmt.Errorf("one of 'good' or 'bad' metric source is required")
	}

	if total.Type != "prometheus" && total.Type != "sloth" {
		return nil, fmt.Errorf("prometheus or sloth query ratio 'total' metric source is required")
	}

	var b bytes.Buffer

	if &sli.RatioMetric.Good.MetricSource != nil {
		if sli.RatioMetric.Good.MetricSource.Type != "prometheus" && sli.RatioMetric.Good.MetricSource.Type != "sloth" {
			return nil, fmt.Errorf("prometheus or sloth query ratio 'good' metric source is required")
		}

		// Map as good and total events as a raw query.
		err := errorRatioRawQueryTpl.Execute(&b, map[string]string{"good": strings.Trim(sli.RatioMetric.Good.MetricSource.MetricSourceSpec["query"], "->"), "total": strings.Trim(total.MetricSourceSpec["query"], "->")})
		if err != nil {
			return nil, fmt.Errorf("could not execute mapping SLI template: %w", err)
		}
	} else {
		if sli.RatioMetric.Bad.MetricSource.Type != "prometheus" && sli.RatioMetric.Bad.MetricSource.Type != "sloth" {
			return nil, fmt.Errorf("prometheus or sloth query ratio 'bad' metric source is required")
		}

		// Map as bad and total events as a raw query.
		b.WriteString("(")
		b.WriteString(strings.Trim(sli.RatioMetric.Bad.MetricSource.MetricSourceSpec["query"], "->"))
		b.WriteString(")")
		b.WriteString(" / ")
		b.WriteString("(")
		b.WriteString(strings.Trim(total.MetricSourceSpec["query"], "->"))
		b.WriteString(")")
	}

	return &prometheus.SLI{Raw: &prometheus.SLIRaw{
		ErrorRatioQuery: b.String(),
	}}, nil
}

// getV1BetaSLOs will try getting all the objectives as individual SLOs, this way we can map
// to what Sloth understands as an SLO, that OpenSLO understands as a list of objectives
// for the same SLO.
func (y YAMLSpecLoader) getV1SLOs(spec openslov1.SLO) ([]prometheus.SLO, error) {
	res := []prometheus.SLO{}
	sli, err := y.getV1SLI(spec.Spec, spec.Spec.Indicator.Spec)
	if err != nil {
		return nil, fmt.Errorf("could not map SLI: %w", err)
	}

	for idx, slo := range spec.Spec.Objectives {

		timeWindow := y.windowPeriod
		if len(spec.Spec.TimeWindow) > 0 {
			sp, err := prometheusmodel.ParseDuration(spec.Spec.TimeWindow[0].Duration)
			if err != nil {
				return nil, fmt.Errorf("invalid SLO time window duration: %w", err)
			}
			timeWindow = time.Duration(sp)
		}

		// TODO(slok): Think about using `slo.Value` insted of idx (`slo.Value` is not mandatory).
		res = append(res, prometheus.SLO{
			ID:              fmt.Sprintf("%s-%s-%d", spec.Spec.Service, spec.Metadata.Name, idx),
			Name:            fmt.Sprintf("%s-%d", spec.Metadata.Name, idx),
			Service:         spec.Spec.Service,
			Description:     spec.Spec.Description,
			TimeWindow:      timeWindow,
			SLI:             *sli,
			Objective:       *&slo.Target * 100, // OpenSLO uses ratios, we use percents.
			PageAlertMeta:   prometheus.AlertMeta{Disable: true},
			TicketAlertMeta: prometheus.AlertMeta{Disable: true},
		})
	}

	return res, nil
}
