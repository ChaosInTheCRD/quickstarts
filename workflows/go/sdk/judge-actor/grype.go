package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/grypeerr"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/presenter/sarif"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/syft/cmd/syft/cli"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/exp/maps"
)

func runGrype(target string) ([]byte, error) {
	app := cli.Application(
		clio.Identification{
			Name: "grype",
		},
	)

	var str *store.Store
	var status *db.Status
	var dbCloser *db.Closer
	var packages []pkg.Package
	var pkgContext pkg.Context
	var errs error

	// all variables here are provided as build-time arguments, with clear default values
	var (
		version        = "[not provided]"
		buildDate      = "[not provided]"
		gitCommit      = "[not provided]"
		gitDescription = "[not provided]"
	)
	id := clio.Identification{
		Name:           "grype",
		Version:        version,
		BuildDate:      buildDate,
		GitCommit:      gitCommit,
		GitDescription: gitDescription,
	}

	opts := options.DefaultGrype(id)

	err := parallel(
		func() (err error) {
			log.Println("loading DB")
			str, status, dbCloser, err = grype.LoadVulnerabilityDB(opts.DB.ToCuratorConfig(), false)
			return validateDBLoad(err, status)
		},
		func() (err error) {
			log.Println("gathering packages")
			// packages are grype.Package, not syft.Package
			// the SBOM is returned for downstream formatting concerns
			// grype uses the SBOM in combination with syft formatters to produce cycloneDX
			// with vulnerability information appended
			packages, pkgContext, _, err = pkg.Provide(target, getProviderConfig(opts))
			if err != nil {
				return fmt.Errorf("failed to catalog: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	if dbCloser != nil {
		defer dbCloser.Close()
	}

	applyDistroHint(packages, &pkgContext, opts)

	vulnMatcher := grype.VulnerabilityMatcher{
		Store:          *str,
		IgnoreRules:    opts.Ignore,
		NormalizeByCVE: opts.ByCVE,
		FailSeverity:   opts.FailOnSeverity(),
		Matchers:       getMatchers(opts),
		VexProcessor: vex.NewProcessor(vex.ProcessorOptions{
			Documents:   opts.VexDocuments,
			IgnoreRules: opts.Ignore,
		}),
	}

	remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		if !errors.Is(err, grypeerr.ErrAboveSeverityThreshold) {
			return nil, err
		}
		errs = appendErrors(errs, err)
	}

	fmt.Println("logging out all the matches")
	for _, match := range remainingMatches.Sorted() {
		fmt.Println(match.Vulnerability.ID)
		fmt.Println(match.Details)
	}
	if errs != nil {
		return nil, errs
	}

	pres := sarif.NewPresenter(models.PresenterConfig{
		ID:               app.ID(),
		Matches:          *remainingMatches,
		IgnoredMatches:   ignoredMatches,
		Packages:         packages,
		Context:          pkgContext,
		MetadataProvider: str,
		// NOTE: We're gonna leave this out for now as I'm not fully sure how it works
		// SBOM:             s,
		AppConfig: opts,
		DBStatus:  status,
	})

	out := bytes.NewBuffer([]byte{})
	err = pres.Present(out)
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// parallel takes a set of functions and runs them in parallel, capturing all errors returned and
// returning the single error returned by one of the parallel funcs, or a multierror.Error with all
// the errors if more than one
func parallel(funcs ...func() error) error {
	errs := parallelMapped(funcs...)
	if len(errs) > 0 {
		values := maps.Values(errs)
		if len(values) == 1 {
			return values[0]
		}
		return multierror.Append(nil, values...)
	}
	return nil
}

// parallelMapped takes a set of functions and runs them in parallel, capturing all errors returned in
// a map indicating which func, by index returned which error
func parallelMapped(funcs ...func() error) map[int]error {
	errs := map[int]error{}
	errorLock := &sync.Mutex{}
	wg := &sync.WaitGroup{}
	wg.Add(len(funcs))
	for i, fn := range funcs {
		go func(i int, fn func() error) {
			defer wg.Done()
			err := fn()
			if err != nil {
				errorLock.Lock()
				defer errorLock.Unlock()
				errs[i] = err
			}
		}(i, fn)
	}
	wg.Wait()
	return errs
}

func validateDBLoad(loadErr error, status *db.Status) error {
	if loadErr != nil {
		return fmt.Errorf("failed to load vulnerability db: %w", loadErr)
	}
	if status == nil {
		return fmt.Errorf("unable to determine the status of the vulnerability db")
	}
	if status.Err != nil {
		return fmt.Errorf("db could not be loaded: %w", status.Err)
	}
	return nil
}

func getProviderConfig(opts *options.Grype) pkg.ProviderConfig {
	cfg := syft.DefaultCreateSBOMConfig()
	cfg.Packages.JavaArchive.IncludeIndexedArchives = opts.Search.IncludeIndexedArchives
	cfg.Packages.JavaArchive.IncludeUnindexedArchives = opts.Search.IncludeUnindexedArchives

	return pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions:        opts.Registry.ToOptions(),
			Exclusions:             opts.Exclusions,
			SBOMOptions:            cfg,
			Platform:               opts.Platform,
			Name:                   opts.Name,
			DefaultImagePullSource: opts.DefaultImagePullSource,
		},
		SynthesisConfig: pkg.SynthesisConfig{
			GenerateMissingCPEs: opts.GenerateMissingCPEs,
		},
	}
}

func applyDistroHint(pkgs []pkg.Package, context *pkg.Context, opts *options.Grype) {
	if opts.Distro != "" {
		log.Printf("using distro: %s\n", opts.Distro)

		split := strings.Split(opts.Distro, ":")
		d := split[0]
		v := ""
		if len(split) > 1 {
			v = split[1]
		}
		context.Distro = &linux.Release{
			PrettyName: d,
			Name:       d,
			ID:         d,
			IDLike: []string{
				d,
			},
			Version:   v,
			VersionID: v,
		}
	}

	hasOSPackage := false
	for _, p := range pkgs {
		switch p.Type {
		case syftPkg.AlpmPkg, syftPkg.DebPkg, syftPkg.RpmPkg, syftPkg.KbPkg:
			hasOSPackage = true
		}
	}

	if context.Distro == nil && hasOSPackage {
		log.Println("Unable to determine the OS distribution. This may result in missing vulnerabilities. " +
			"You may specify a distro using: --distro <distro>:<version>")
	}
}

func getMatchers(opts *options.Grype) []matcher.Matcher {
	return matcher.NewDefaultMatchers(
		matcher.Config{
			Java: java.MatcherConfig{
				ExternalSearchConfig: opts.ExternalSources.ToJavaMatcherConfig(),
				UseCPEs:              opts.Match.Java.UseCPEs,
			},
			Ruby:       ruby.MatcherConfig(opts.Match.Ruby),
			Python:     python.MatcherConfig(opts.Match.Python),
			Dotnet:     dotnet.MatcherConfig(opts.Match.Dotnet),
			Javascript: javascript.MatcherConfig(opts.Match.Javascript),
			Golang: golang.MatcherConfig{
				UseCPEs:                                opts.Match.Golang.UseCPEs,
				AlwaysUseCPEForStdlib:                  opts.Match.Golang.AlwaysUseCPEForStdlib,
				AllowMainModulePseudoVersionComparison: opts.Match.Golang.AllowMainModulePseudoVersionComparison,
			},
			Stock: stock.MatcherConfig(opts.Match.Stock),
		},
	)
}

func appendErrors(errs error, err ...error) error {
	if errs == nil {
		switch len(err) {
		case 0:
			return nil
		case 1:
			return err[0]
		}
	}
	return multierror.Append(errs, err...)
}
