//
// Copyright 2023 The Sigstore Authors.
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
	"crypto"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
)

// TODO: Maybe move this to pkg/cosign?

// VerifyConfig helps construct a CheckOpts object that can be used
// as the baseline for various verification methods.
type CheckConfig struct {
	options.RegistryOptions
	options.CertVerifyOptions
	KeyRef  string
	CertRef string
	// TODO: These overlap with CertVerifyOptions. What are the ramifications?
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	CertChain                    string
	IgnoreSCT                    bool
	// TODO: End of overlap
	SCTRef           string
	Sk               bool
	Slot             string
	RekorURL         string
	Offline          bool
	TSACertChainPath string
	IgnoreTlog       bool
	HashAlgorithm    crypto.Hash
}

func (c *CheckConfig) SetDefaults() {
	// always default to sha256 if the algorithm hasn't been explicitly set
	if c.HashAlgorithm == 0 {
		c.HashAlgorithm = crypto.SHA256
	}
}

func (c *CheckConfig) Validate() error {
	// Key and security key are mutually exclusive
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	return nil
}

func (c *CheckConfig) ToCheckOpts(ctx context.Context) (*cosign.CheckOpts, error) {
	var err error

	var identities []cosign.Identity
	if c.KeyRef == "" {
		identities, err = c.Identities()
		if err != nil {
			return nil, err
		}
	}

	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("constructing client options: %w", err)
	}

	co := &cosign.CheckOpts{
		RegistryClientOpts:           ociremoteOpts,
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSha,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		Identities:                   identities,
		Offline:                      c.Offline,
		IgnoreTlog:                   c.IgnoreTlog,
	}

	if !c.IgnoreSCT {
		if co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx); err != nil {
			return nil, fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}

	if c.TSACertChainPath != "" {
		if _, err := os.Stat(c.TSACertChainPath); err != nil {
			return nil, fmt.Errorf("unable to open timestamp certificate chain file: %w", err)
		}
		// TODO: Add support for TUF certificates.
		pemBytes, err := os.ReadFile(filepath.Clean(c.TSACertChainPath))
		if err != nil {
			return nil, fmt.Errorf("error reading certification chain path file: %w", err)
		}

		leaves, intermediates, roots, err := tsa.SplitPEMCertificateChain(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("error splitting certificates: %w", err)
		}
		if len(leaves) > 1 {
			return nil, fmt.Errorf("certificate chain must contain at most one TSA certificate")
		}
		if len(leaves) == 1 {
			co.TSACertificate = leaves[0]
		}
		co.TSAIntermediateCertificates = intermediates
		co.TSARootCertificates = roots
	}

	if !c.IgnoreTlog {
		if c.RekorURL != "" {
			if co.RekorClient, err = rekor.NewClient(c.RekorURL); err != nil {
				return nil, fmt.Errorf("creating Rekor client: %w", err)
			}
		}
		// This performs an online fetch of the Rekor public keys, but this is needed
		// for verifying tlog entries (both online and offline).
		if co.RekorPubKeys, err = cosign.GetRekorPubs(ctx); err != nil {
			return nil, fmt.Errorf("getting Rekor public keys: %w", err)
		}
	}

	if keylessVerification(c.KeyRef, c.Sk) {
		// This performs an online fetch of the Fulcio roots. This is needed
		// for verifying keyless certificates (both online and offline).
		if co.RootCerts, err = fulcio.GetRoots(); err != nil {
			return nil, fmt.Errorf("getting Fulcio roots: %w", err)
		}
		if co.IntermediateCerts, err = fulcio.GetIntermediates(); err != nil {
			return nil, fmt.Errorf("getting Fulcio intermediates: %w", err)
		}
	}

	// Keys are optional!
	switch {
	case c.KeyRef != "":
		if co.SigVerifier, err = sigs.PublicKeyFromKeyRefWithHashAlgo(ctx, c.KeyRef, c.HashAlgorithm); err != nil {
			return nil, fmt.Errorf("loading public key: %w", err)
		}
		if pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key); ok {
			defer pkcs11Key.Close()
		}
	case c.Sk:
		sk, err := pivkey.GetKeyWithSlot(c.Slot)
		if err != nil {
			return nil, fmt.Errorf("opening piv token: %w", err)
		}
		defer sk.Close()
		co.SigVerifier, err = sk.Verifier()
		if err != nil {
			return nil, fmt.Errorf("initializing piv token verifier: %w", err)
		}
	case c.CertRef != "":
		cert, err := loadCertFromFileOrURL(c.CertRef)
		if err != nil {
			return nil, fmt.Errorf("loading certificate from reference: %w", err)
		}
		if c.CertChain == "" {
			// If no certChain is passed, the Fulcio root certificate will be used
			co.RootCerts, err = fulcio.GetRoots()
			if err != nil {
				return nil, fmt.Errorf("getting Fulcio roots: %w", err)
			}
			co.IntermediateCerts, err = fulcio.GetIntermediates()
			if err != nil {
				return nil, fmt.Errorf("getting Fulcio intermediates: %w", err)
			}
			co.SigVerifier, err = cosign.ValidateAndUnpackCert(cert, co)
			if err != nil {
				return nil, fmt.Errorf("creating certificate verifier: %w", err)
			}
		} else {
			// Verify certificate with chain
			chain, err := loadCertChainFromFileOrURL(c.CertChain)
			if err != nil {
				return nil, err
			}
			if co.SigVerifier, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co); err != nil {
				return nil, err
			}
		}
		if c.SCTRef != "" {
			if co.SCT, err = os.ReadFile(filepath.Clean(c.SCTRef)); err != nil {
				return nil, fmt.Errorf("reading sct from file: %w", err)
			}
		}
	}

	return co, nil
}
