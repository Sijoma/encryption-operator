package diskclient

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
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
	diskClient := DiskClient{
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
	keyID := keyParts[0]
	keyVersion := keyParts[1]
	if keyVersion == "" {
		return nil, fmt.Errorf("invalid key version")
	}
	keyVersion, err := getKeyVersion(result.keyPrincipal)
	if err != nil {
		return nil, err
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
	regionOrZoneDetect := detectZoneOrRegion(regionOrZone)

	var disk *computepb.Disk
	var err error
	switch regionOrZoneDetect {
	case "zone":
		disk, err = d.zonal.Get(ctx, &computepb.GetDiskRequest{
			Disk:    pv.Name,
			Project: project,
			Zone:    regionOrZone,
		})
		if err != nil {
			return nil, err
		}
	case "region":
		disk, err = d.regional.Get(ctx, &computepb.GetRegionDiskRequest{
			Disk:    pv.Name,
			Project: project,
			Region:  regionOrZone,
		})
		if err != nil {
			return nil, err
		}
	case "invalid":
		return nil, fmt.Errorf("unable to detect if disk is zonal or regional")
	default:
		return nil, fmt.Errorf("nothing matched")
	}
	return disk, nil
}

func detectZoneOrRegion(input string) string {
	zonePattern := `^[a-z]+-[a-z]+\d-[a-z]$`
	regionPattern := `^[a-z]+-[a-z]+\d$`

	isZone, _ := regexp.MatchString(zonePattern, input)
	if isZone {
		return "zone"
	}

	isRegion, _ := regexp.MatchString(regionPattern, input)
	if isRegion {
		return "region"
	}

	return "invalid"
}
