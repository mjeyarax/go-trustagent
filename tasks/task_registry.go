package tasks

import (
	log "github.com/sirupsen/logrus"

	"intel/isecl/lib/common/setup"
	"intel/isecl/go-trust-agent/config"
)

type TaskRegistry struct {
	taskMap map[string][]setup.Task
}

const (
	SetupAllCommand			= "all"
	TakeOwnershipCommand 	= "takeownership"
)

func CreateTaskRegistry(cfg *config.TrustAgentConfiguration, flags []string) (TaskRegistry, error) {

	var registry TaskRegistry
	registry.taskMap = make(map[string][]setup.Task)

	takeOwnership := TakeOwnership {Flags : flags, Config : cfg}

	registry.taskMap[TakeOwnershipCommand] = []setup.Task { &takeOwnership, }

	registry.taskMap[SetupAllCommand] = []setup.Task {
		&takeOwnership,
	}

	return registry, nil
}

func (registry *TaskRegistry) RunCommand(command string) error {
	tasks := registry.taskMap[command]
	setupRunner := &setup.Runner {
		Tasks: tasks,
		AskInput: false,
	}

	err := setupRunner.RunTasks()
	if err != nil {
		log.WithError(err).Error("Error running setup")
		return err
	}

	return nil
}