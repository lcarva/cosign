//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/cue"
	"github.com/sigstore/cosign/v2/pkg/cosign/rego"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/policy"
)

// VerifyAttestationCommand verifies a signature on a supplied container image
// nolint
type VerifyAttestationCommand struct {
	options.RegistryOptions
	options.CertVerifyOptions
	CheckClaims                  bool
	KeyRef                       string
	CertRef                      string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	CertChain                    string
	IgnoreSCT                    bool
	SCTRef                       string
	Sk                           bool
	Slot                         string
	// TODO: Where's this used?
	Output           string
	RekorURL         string
	PredicateType    string
	Policies         []string
	LocalImage       bool
	NameOptions      []name.Option
	Offline          bool
	TSACertChainPath string
	IgnoreTlog       bool
}

// Exec runs the verification command
func (c *VerifyAttestationCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	config := CheckConfig{
		RegistryOptions:              c.RegistryOptions,
		CertVerifyOptions:            c.CertVerifyOptions,
		KeyRef:                       c.KeyRef,
		CertRef:                      c.CertRef,
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSha,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		CertChain:                    c.CertChain,
		IgnoreSCT:                    c.IgnoreSCT,
		SCTRef:                       c.SCTRef,
		Sk:                           c.Sk,
		Slot:                         c.Slot,
		RekorURL:                     c.RekorURL,
		Offline:                      c.Offline,
		TSACertChainPath:             c.TSACertChainPath,
		IgnoreTlog:                   c.IgnoreTlog,
	}

	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return err
	}

	co, err := config.ToCheckOpts(ctx)
	if err != nil {
		return err
	}

	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}

	// NB: There are only 2 kinds of verification right now:
	// 1. You gave us the public key explicitly to verify against so co.SigVerifier is non-nil or,
	// 2. We're going to find an x509 certificate on the signature and verify against Fulcio root trust
	// TODO(nsmith5): Refactor this verification logic to pass back _how_ verification
	// was performed so we don't need to use this fragile logic here.
	fulcioVerified := (co.SigVerifier == nil)

	for _, imageRef := range images {
		var verified []oci.Signature
		var bundleVerified bool

		if c.LocalImage {
			verified, bundleVerified, err = cosign.VerifyLocalImageAttestations(ctx, imageRef, co)
			if err != nil {
				return err
			}
		} else {
			ref, err := name.ParseReference(imageRef, c.NameOptions...)
			if err != nil {
				return err
			}

			verified, bundleVerified, err = cosign.VerifyImageAttestations(ctx, ref, co)
			if err != nil {
				return err
			}
		}

		var cuePolicies, regoPolicies []string

		for _, policy := range c.Policies {
			switch filepath.Ext(policy) {
			case ".rego":
				regoPolicies = append(regoPolicies, policy)
			case ".cue":
				cuePolicies = append(cuePolicies, policy)
			default:
				return errors.New("invalid policy format, expected .cue or .rego")
			}
		}

		var checked []oci.Signature
		var validationErrors []error
		// To aid in determining if there's a mismatch in what predicateType
		// we're looking for and what we checked, keep track of them here so
		// that we can help the user figure out if there's a typo, etc.
		checkedPredicateTypes := []string{}
		for _, vp := range verified {
			payload, gotPredicateType, err := policy.AttestationToPayloadJSON(ctx, c.PredicateType, vp)
			if err != nil {
				return fmt.Errorf("converting to consumable policy validation: %w", err)
			}
			checkedPredicateTypes = append(checkedPredicateTypes, gotPredicateType)
			if len(payload) == 0 {
				// This is not the predicate type we're looking for.
				continue
			}

			if len(cuePolicies) > 0 {
				ui.Infof(ctx, "will be validating against CUE policies: %v", cuePolicies)
				cueValidationErr := cue.ValidateJSON(payload, cuePolicies)
				if cueValidationErr != nil {
					validationErrors = append(validationErrors, cueValidationErr)
					continue
				}
			}

			if len(regoPolicies) > 0 {
				ui.Infof(ctx, "will be validating against Rego policies: %v", regoPolicies)
				regoValidationErrs := rego.ValidateJSON(payload, regoPolicies)
				if len(regoValidationErrs) > 0 {
					validationErrors = append(validationErrors, regoValidationErrs...)
					continue
				}
			}

			checked = append(checked, vp)
		}

		if len(validationErrors) > 0 {
			ui.Infof(ctx, "There are %d number of errors occurred during the validation:\n", len(validationErrors))
			for _, v := range validationErrors {
				ui.Infof(ctx, "- %v", v)
			}
			return fmt.Errorf("%d validation errors occurred", len(validationErrors))
		}

		if len(checked) == 0 {
			return fmt.Errorf("none of the attestations matched the predicate type: %s, found: %s", c.PredicateType, strings.Join(checkedPredicateTypes, ","))
		}

		// TODO: add CUE validation report to `PrintVerificationHeader`.
		PrintVerificationHeader(ctx, imageRef, co, bundleVerified, fulcioVerified)
		// The attestations are always JSON, so use the raw "text" mode for outputting them instead of conversion
		PrintVerification(ctx, imageRef, checked, "text")
	}

	return nil
}
