package tasks

import (
	"errors"

	log "github.com/sirupsen/logrus"

	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/tpmprovider"
	"intel/isecl/lib/common/crypt"
	"intel/isecl/lib/common/setup"
)

type TakeOwnership struct {
	Flags 	[]string
	Config 	*config.TrustAgentConfiguration
}

func (task* TakeOwnership) Run(c setup.Context) error {
	log.Info("TakeOwnership Run")
	var err error

	tpmProvider, err := tpmprovider.NewTpmProvider()
	defer tpmProvider.Close()
	if err != nil {
		return err
	}

	if task.Config.Tpm.SecretKey == nil {
		task.Config.Tpm.SecretKey, err = crypt.GetRandomBytes(20)
		if err != nil {
			return errors.New("An error occurred generating a random key")
		}

		// TODO: Save config file
	}
	
	err = tpmProvider.TakeOwnership(task.Config.Tpm.SecretKey)
	if err != nil {
		return err
	}
	
	return nil
}

func (task* TakeOwnership) Validate(c setup.Context) error {
	log.Info("TakeOwnership Validate")

	t, err := tpmprovider.NewTpmProvider()
	defer t.Close()
	if err != nil {
		return err
	}

	if task.Config.Tpm.SecretKey == nil {
		return errors.New("The configuration does not contain the tpm secret key")
	}

	ok, err := t.IsOwnedWithAuth(task.Config.Tpm.SecretKey)
	if !ok {
		return errors.New("The tpm is not owned with the current secret key")
	}

	if err != nil {
		return errors.New("IsOwnedWithAuth returned an error")
	}

	return nil
}