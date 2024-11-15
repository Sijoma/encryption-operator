package diskclient

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	v1 "k8s.io/api/core/v1"
)

type GCP struct {
	zonal    *compute.DisksClient
	regional *compute.RegionDisksClient
}

func NewGCP(ctx context.Context) (*GCP, error) {
	zonalClient, err := compute.NewDisksRESTClient(ctx)
	if err != nil {
		return nil, err
	}

	regionalClient, err := compute.NewRegionDisksRESTClient(ctx)
	if err != nil {
		return nil, err
	}
	diskClient := GCP{
		zonal:    zonalClient,
		regional: regionalClient,
	}
	return &diskClient, nil
}

type EncryptionKeyPrincipal struct {
	keyPrincipal string
	keyVersion   string
}

func (e EncryptionKeyPrincipal) KeyPrincipal() string { return e.keyPrincipal }
func (e EncryptionKeyPrincipal) KeyVersion() string   { return e.keyVersion }
func (e EncryptionKeyPrincipal) IsEncrypted() bool {
	return e.KeyPrincipal() != "" && e.KeyVersion() != ""
}

func (d GCP) GetEncryptionKeyPrincipal(ctx context.Context, pv v1.PersistentVolume) (*EncryptionKeyPrincipal, error) {
	result := EncryptionKeyPrincipal{}

	disk, err := d.getDisk(ctx, pv)
	if err != nil {
		return nil, err
	}
	if disk.DiskEncryptionKey == nil {
		return nil, nil
	}

	result.keyPrincipal = disk.DiskEncryptionKey.GetKmsKeyName()
	// Get KeyID
	keyParts := strings.Split(result.keyPrincipal, "/cryptoKeyVersions/")
	keyVersion := keyParts[1]
	if keyVersion == "" {
		return nil, fmt.Errorf("invalid key version")
	}
	result.keyVersion = keyVersion

	return &result, nil
}

func (d GCP) getDisk(ctx context.Context, pv v1.PersistentVolume) (*computepb.Disk, error) {
	volumeHandle := pv.Spec.CSI.VolumeHandle
	if volumeHandle == "" {
		return nil, fmt.Errorf("pv %s does not have a volume handle - so its not encrypted - nothing to do", pv.Name)
	}
	path := strings.Split(volumeHandle, "/")
	project := path[1]
	regionOrZone := path[3]
	regionOrZoneDetect, err := detectZoneOrRegion(regionOrZone)
	if err != nil {
		return nil, err
	}

	switch regionOrZoneDetect {
	case "zone":
		return d.zonal.Get(ctx, &computepb.GetDiskRequest{
			Disk:    pv.Name,
			Project: project,
			Zone:    regionOrZone,
		})
	case "region":
		return d.regional.Get(ctx, &computepb.GetRegionDiskRequest{
			Disk:    pv.Name,
			Project: project,
			Region:  regionOrZone,
		})
	default:
		return nil, fmt.Errorf("nothing matched")
	}
}

func detectZoneOrRegion(input string) (string, error) {
	zonePattern := `^[a-z]+-[a-z]+\d-[a-z]$`
	regionPattern := `^[a-z]+-[a-z]+\d$`

	isZone, _ := regexp.MatchString(zonePattern, input)
	if isZone {
		return "zone", nil
	}

	isRegion, _ := regexp.MatchString(regionPattern, input)
	if isRegion {
		return "region", nil
	}

	return "", fmt.Errorf("unable to detect region from input: %s", input)
}
