/*
Copyright 2022 k0s authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package v1beta1

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	utilnet "k8s.io/utils/net"
)

var _ Validateable = (*Network)(nil)

// Network defines the network related config options
type Network struct {
	Calico     *Calico     `json:"calico"`
	KubeProxy  *KubeProxy  `json:"kubeProxy"`
	KubeRouter *KubeRouter `json:"kuberouter"`

	// Pod network CIDR to use in the cluster
	PodCIDR string `json:"podCIDR"`
	// Network provider (valid values: calico, kuberouter, or custom)
	Provider string `json:"provider"`
	// Network CIDR to use for cluster VIP services
	ServiceCIDR string `json:"serviceCIDR,omitempty"`
}

// DefaultNetwork creates the Network config struct with sane default values
func DefaultNetwork() *Network {
	return &Network{
		PodCIDR:     "10.244.0.0/16",
		ServiceCIDR: "10.96.0.0/12",
		Provider:    "kuberouter",
		KubeRouter:  DefaultKubeRouter(),
		KubeProxy:   DefaultKubeProxy(),
	}
}

// Validate validates all the settings make sense and should work
func (n *Network) Validate() []error {
	var errors []error
	if n.Provider != "calico" && n.Provider != "custom" && n.Provider != "kuberouter" {
		errors = append(errors, fmt.Errorf("unsupported network provider: %s", n.Provider))
	}

	_, err := utilnet.ParseCIDRs(strings.Split(n.PodCIDR, ","))
	if err != nil {
		errors = append(errors, fmt.Errorf("invalid pod CIDR %s", n.PodCIDR))
	}

	_, err = utilnet.ParseCIDRs(strings.Split(n.ServiceCIDR, ","))
	if err != nil {
		errors = append(errors, fmt.Errorf("invalid service CIDR %s", n.ServiceCIDR))
	}

	if n.IsDualStack() {
		if n.Provider == "calico" && n.Calico.Mode != "bird" {
			errors = append(errors, fmt.Errorf("network dual stack is supported only for calico mode `bird`"))
		}
	}
	errors = append(errors, n.KubeProxy.Validate()...)
	return errors
}

// DNSAddress calculates the 10th address of the first configured service CIDR block.
func (n *Network) DNSAddress() (string, error) {
	parsedCIDRs, err := utilnet.ParseCIDRs(strings.Split(n.ServiceCIDR, ","))
	if err != nil {
		return "", fmt.Errorf("failed to parse service CIDR %s: %w", n.ServiceCIDR, err)
	}
	if len(parsedCIDRs) == 0 {
		return "", errors.New("received empty ServiceCIDR")
	}

	ipnet := parsedCIDRs[0]

	address := ipnet.IP.To4()
	if IsIPv6String(ipnet.IP.String()) {
		address = ipnet.IP.To16()
	}

	prefixlen, _ := ipnet.Mask.Size()
	if prefixlen < 29 {
		address[3] = address[3] + 10
	} else {
		address[3] = address[3] + 2
	}

	if !ipnet.Contains(address) {
		return "", fmt.Errorf("failed to calculate a valid DNS address: %s", address.String())
	}

	return address.String(), nil
}

// InternalAPIAddresses calculates the internal API address of configured service CIDR block.
func (n *Network) InternalAPIAddresses() ([]string, error) {
	parsedCIDRs, err := utilnet.ParseCIDRs(strings.Split(n.ServiceCIDR, ","))
	if err != nil {
		return nil, fmt.Errorf("can't parse service cidr to build internal API address: %w", err)
	}

	stringifiedAddresses := make([]string, len(parsedCIDRs))
	for i, ip := range parsedCIDRs {
		apiIP, err := utilnet.GetIndexedIP(ip, 1)
		if err != nil {
			return nil, fmt.Errorf("can't build internal API address: %v", err)
		}
		stringifiedAddresses[i] = apiIP.String()
	}
	return stringifiedAddresses, nil
}

// UnmarshalJSON sets in some sane defaults when unmarshaling the data from json
func (n *Network) UnmarshalJSON(data []byte) error {
	n.Provider = "calico"

	type network Network
	jc := (*network)(n)

	if err := json.Unmarshal(data, jc); err != nil {
		return err
	}

	if n.Provider == "calico" && n.Calico == nil {
		n.Calico = DefaultCalico()
		n.KubeRouter = nil
	} else if n.Provider == "kuberouter" && n.KubeRouter == nil {
		n.KubeRouter = DefaultKubeRouter()
		n.Calico = nil
	}

	if n.KubeProxy == nil {
		n.KubeProxy = DefaultKubeProxy()
	}

	return nil
}

// BuildServiceCIDR returns actual argument value for service cidr
func (n *Network) BuildServiceCIDR(addr string) string {
	// serviceCIDR is already in the proper order so just return it.
	return n.ServiceCIDR
}

// BuildPodCIDR returns actual argument value for pod cidr
func (n *Network) BuildPodCIDR() string {
	// podCIDR is already in the proper order so just return it.
	return n.PodCIDR
}

// Returns whether this cluster has a pure ipv6 network.
func (n *Network) IsIPv6() bool {
	v4Found := false
	v6Found := false

	subnets, _ := utilnet.ParseCIDRs(strings.Split(n.PodCIDR, ","))
	for _, podSubnet := range subnets {
		if podSubnet == nil {
			continue
		}
		if utilnet.IsIPv6(podSubnet.IP) {
			v6Found = true
		} else {
			v4Found = true
		}
	}
	return v6Found && !v4Found
}

// Returns whether this cluster has a dualstack network.
func (n *Network) IsDualStack() bool {
	result, _ := utilnet.IsDualStackCIDRStrings(strings.Split(n.PodCIDR, ","))
	return result
}

// Returns 2 comma delimited strings of ipv4, ipv6 subnets from PodCIDR.
func (n *Network) GetPodCIDRsByFamily() (string, string) {
	v4nets := []string{}
	v6nets := []string{}

	subnets, _ := utilnet.ParseCIDRs(strings.Split(n.PodCIDR, ","))
	for _, podSubnet := range subnets {
		if utilnet.IsIPv6(podSubnet.IP) {
			v6nets = append(v6nets, podSubnet.String())
		} else {
			v4nets = append(v4nets, podSubnet.String())
		}
	}

	return strings.Join(v4nets, ","), strings.Join(v6nets, ",")
}
