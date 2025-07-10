package swarmcd

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/flags"
	"log/slog"
	"os"
	"path"
	"strconv"
	"strings"
	"text/template"

	"github.com/docker/cli/cli/command/service"
	"github.com/docker/cli/cli/command/stack"
	"github.com/goccy/go-yaml"
	"github.com/m-adawi/swarm-cd/util"
)

type swarmStack struct {
	name            string
	repo            *stackRepo
	branch          string
	composePath     string
	sopsFiles       []string
	valuesFile      string
	discoverSecrets bool
}

func newSwarmStack(name string, repo *stackRepo, branch string, composePath string, sopsFiles []string, valuesFile string, discoverSecrets bool) *swarmStack {
	return &swarmStack{
		name:            name,
		repo:            repo,
		branch:          branch,
		composePath:     composePath,
		sopsFiles:       sopsFiles,
		valuesFile:      valuesFile,
		discoverSecrets: discoverSecrets,
	}
}

func (swarmStack *swarmStack) updateStack() (revision string, err error) {
	log := logger.With(
		slog.String("stack", swarmStack.name),
		slog.String("branch", swarmStack.branch),
	)

	log.Debug("pulling changes...")
	revision, err = swarmStack.repo.pullChanges(swarmStack.branch)
	if err != nil {
		return
	}
	log.Debug("changes pulled", "revision", revision)

	log.Debug("reading stack file...")
	stackBytes, err := swarmStack.readStack()
	if err != nil {
		return
	}

	log.Debug("decrypting declared sops files...")
	err = swarmStack.decryptSopsFiles(swarmStack.sopsFiles)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt one or more sops files for %s stack: %w", swarmStack.name, err)
	}

	if swarmStack.valuesFile != "" {
		log.Debug("rendering template...")
		stackBytes, err = swarmStack.renderComposeTemplate(stackBytes)
	}
	if err != nil {
		return
	}

	log.Debug("parsing stack content...")
	stackContents, err := swarmStack.parseStackString([]byte(stackBytes))
	if err != nil {
		return
	}

	if swarmStack.discoverSecrets {
		log.Debug("decrypting secrets...")
		sopsFiles, err := discoverSecrets(stackContents, swarmStack.composePath)
		if err != nil {
			return "", fmt.Errorf("failed to discover sops encrypted secrets for %s stack: %w", swarmStack.name, err)
		}
		err = swarmStack.decryptSopsFiles(sopsFiles)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt one or more sops files for %s stack: %w", swarmStack.name, err)
		}
	}

	log.Debug("rotating configs and secrets...")
	err = swarmStack.rotateConfigsAndSecrets(stackContents)
	if err != nil {
		return
	}

	log.Debug("preserving service replica counts...")
	err = swarmStack.preserveServiceReplicas(stackContents)
	if err != nil {
		return
	}

	log.Debug("writing stack to file...")
	err = swarmStack.writeStack(stackContents)
	if err != nil {
		return
	}

	log.Debug("deploying stack...")
	err = swarmStack.deployStack()
	return
}

func (swarmStack *swarmStack) readStack() ([]byte, error) {
	composeFile := path.Join(swarmStack.repo.path, swarmStack.composePath)
	composeFileBytes, err := os.ReadFile(composeFile)
	if err != nil {
		return nil, fmt.Errorf("could not read compose file %s: %w", composeFile, err)
	}
	return composeFileBytes, nil
}

func (swarmStack *swarmStack) renderComposeTemplate(templateContents []byte) ([]byte, error) {
	valuesFile := path.Join(swarmStack.repo.path, swarmStack.valuesFile)
	valuesBytes, err := os.ReadFile(valuesFile)
	if err != nil {
		return nil, fmt.Errorf("could not read %s stack values file: %w", swarmStack.name, err)
	}
	var valuesMap map[string]any
	yaml.Unmarshal(valuesBytes, &valuesMap)
	templ, err := template.New(swarmStack.name).Parse(string(templateContents[:]))
	if err != nil {
		return nil, fmt.Errorf("could not parse %s stack compose file as a Go template: %w", swarmStack.name, err)
	}
	var stackContents bytes.Buffer
	err = templ.Execute(&stackContents, map[string]map[string]any{"Values": valuesMap})
	if err != nil {
		return nil, fmt.Errorf("error rending %s stack compose template: %w", swarmStack.name, err)
	}
	return stackContents.Bytes(), nil
}

func (swarmStack *swarmStack) parseStackString(stackContent []byte) (map[string]any, error) {
	var composeMap map[string]any
	err := yaml.Unmarshal(stackContent, &composeMap)
	if err != nil {
		return nil, fmt.Errorf("could not parse stack yaml: %w", err)
	}
	return composeMap, nil
}

func (swarmStack *swarmStack) decryptSopsFiles(sopsFiles []string) (err error) {
	log := logger.With(
		slog.String("stack", swarmStack.name),
		slog.String("branch", swarmStack.branch),
	)
	for _, sopsFile := range sopsFiles {
		log.Debug("decrypting secret...", "secret", sopsFile)
		err = util.DecryptFile(path.Join(swarmStack.repo.path, sopsFile))
		if err != nil {
			return
		}
	}
	return
}

func discoverSecrets(composeMap map[string]any, composePath string) ([]string, error) {
	var sopsFiles []string
	if secrets, ok := composeMap["secrets"].(map[string]any); ok {
		for secretName, secret := range secrets {
			secretMap, ok := secret.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid compose file: %s secret must be a map", secretName)
			}
			isExternal, ok := secretMap["external"].(bool)
			if ok && isExternal {
				continue
			}
			secretFile, ok := secretMap["file"].(string)
			if !ok {
				return nil, fmt.Errorf("invalid compose file: %s file field must be a string", secretName)
			}
			secretPath := path.Join(path.Dir(composePath), secretFile)
			sopsFiles = append(sopsFiles, secretPath)
		}
	}
	return sopsFiles, nil
}

func (swarmStack *swarmStack) rotateConfigsAndSecrets(composeMap map[string]any) error {
	if configs, ok := composeMap["configs"].(map[string]any); ok {
		err := swarmStack.rotateObjects(configs, "configs")
		if err != nil {
			return fmt.Errorf("could not rotate one or more config files of stack %s: %w", swarmStack.name, err)
		}
	}
	if secrets, ok := composeMap["secrets"].(map[string]any); ok {
		err := swarmStack.rotateObjects(secrets, "secrets")
		if err != nil {
			return fmt.Errorf("could not rotate one or more secret files of stack %s: %w", swarmStack.name, err)
		}
	}
	return nil
}

func (swarmStack *swarmStack) rotateObjects(objects map[string]any, objectType string) error {
	objectsDir := path.Dir(path.Join(swarmStack.repo.path, swarmStack.composePath))
	for objectName, object := range objects {
		log := logger.With(
			slog.String("stack", swarmStack.name),
			slog.String("branch", swarmStack.branch),
			slog.String(objectType, objectName),
		)
		objectMap, ok := object.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid compose file: %s object must be a map", objectName)
		}
		isExternal, ok := objectMap["external"].(bool)
		if ok && isExternal {
			continue
		}
		objectFile, ok := objectMap["file"].(string)
		if !ok {
			return fmt.Errorf("invalid compose file: %s file field must be a string", objectName)
		}
		log.Debug("reading...", "file", objectFile)
		objectFilePath := path.Join(objectsDir, objectFile)
		configFileBytes, err := os.ReadFile(objectFilePath)
		if err != nil {
			return fmt.Errorf("could not read file %s for rotation: %w", objectFilePath, err)
		}
		log.Debug("computing hash...", "file", objectFile)
		hash := fmt.Sprintf("%x", md5.Sum(configFileBytes))[:8]
		newObjectName := swarmStack.name + "-" + objectName + "-" + hash
		log.Debug("renaming...", "new_name", newObjectName)
		objectMap["name"] = newObjectName
	}
	return nil
}

func (swarmStack *swarmStack) writeStack(composeMap map[string]any) error {
	composeFileBytes, err := yaml.Marshal(composeMap)
	if err != nil {
		return fmt.Errorf("could not store compose file as yaml after calculating hashes for stack %s", swarmStack.name)
	}
	composeFile := path.Join(swarmStack.repo.path, swarmStack.composePath)
	fileInfo, _ := os.Stat(composeFile)
	os.WriteFile(composeFile, composeFileBytes, fileInfo.Mode())
	return nil
}

// getServiceReplicas gets the current replica count for a service in the swarm
// Returns the replica count and whether the service exists
func (swarmStack *swarmStack) getServiceReplicas(serviceName string) (int, bool, error) {
	// Create a buffer to capture output
	outputBuffer := new(bytes.Buffer)
	// The inspect command use DockerCli.Out()
	dockerCliWithOutput, err := command.NewDockerCli(
		command.WithOutputStream(outputBuffer),
		command.WithErrorStream(outputBuffer),
	)
	if err != nil {
		logger.Warn("could not create docker cli", "error", err)
		return 0, false, fmt.Errorf("could not create docker cli: %w", err)
	}
	err = dockerCliWithOutput.Initialize(flags.NewClientOptions())
	if err != nil {
		logger.Warn("could not initialize docker cli", "error", err)
		return 0, false, fmt.Errorf("could not initialize docker cli: %w", err)
	}
	// close the client
	defer func(cli *command.DockerCli) {
		err := cli.Client().Close()
		if err != nil {
			logger.Warn("could not close docker client", "error", err)
		}
	}(dockerCliWithOutput)

	cmd := service.NewServiceCommand(dockerCliWithOutput)

	// Use service inspect to get service details
	cmd.SetArgs([]string{"inspect", "--format", "{{.Spec.Mode.Replicated.Replicas}}", serviceName})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	err = cmd.Execute()
	if err != nil {
		logger.Warn("error when getting replicas", "service", serviceName, "error", err)
		// Service doesn't exist
		return 0, false, nil
	}

	output := strings.TrimSpace(outputBuffer.String())
	if output == "" || output == "<nil>" {
		// Service exists but is not in replicated mode (might be global)
		return 0, false, nil
	}

	replicas, err := strconv.Atoi(output)
	if err != nil {
		return 0, false, fmt.Errorf("could not parse replica count for service %s: %w", serviceName, err)
	}

	return replicas, true, nil
}

// preserveServiceReplicas scans the stack contents for replicated services and preserves their current replica counts
func (swarmStack *swarmStack) preserveServiceReplicas(stackContents map[string]any) error {
	log := logger.With(
		slog.String("stack", swarmStack.name),
		slog.String("branch", swarmStack.branch),
	)

	services, ok := stackContents["services"].(map[string]any)
	if !ok {
		// No services section, nothing to do
		return nil
	}

	for serviceName, service := range services {
		serviceMap, ok := service.(map[string]any)
		if !ok {
			continue
		}

		// Check if this service uses replicated mode (either explicitly or implicitly)
		if !swarmStack.isReplicatedService(serviceMap) {
			continue
		}

		// Construct the full service name as it appears in Docker Swarm
		fullServiceName := swarmStack.name + "_" + serviceName

		// Get current replica count from the swarm
		currentReplicas, exists, err := swarmStack.getServiceReplicas(fullServiceName)
		if err != nil {
			log.Warn("failed to get replica count for service", "service", fullServiceName, "error", err)
			continue
		}

		if !exists {
			// Service doesn't exist in swarm, keep the compose file value
			log.Debug("service does not exist in swarm, keeping compose file value", "service", fullServiceName)
			continue
		}

		// Service exists, preserve its current replica count
		log.Info("preserving current replica count", "service", fullServiceName, "replicas", currentReplicas)

		// Update the deploy section with the current replica count
		deploy, ok := serviceMap["deploy"].(map[string]any)
		if !ok {
			deploy = make(map[string]any)
			serviceMap["deploy"] = deploy
		}

		deploy["replicas"] = currentReplicas
	}

	return nil
}

// isReplicatedService checks if a service is using replicated mode
func (swarmStack *swarmStack) isReplicatedService(serviceMap map[string]any) bool {
	deploy, ok := serviceMap["deploy"].(map[string]any)
	if !ok {
		// No deploy section means default replicated mode
		return true
	}

	mode, ok := deploy["mode"].(string)
	if !ok {
		// No mode specified means default replicated mode
		return true
	}

	// Only replicated mode services should have their replicas preserved
	return mode == "replicated"
}

func (swarmStack *swarmStack) deployStack() error {
	cmd := stack.NewStackCommand(dockerCli)
	cmd.SetArgs([]string{
		"deploy", "--detach", "--prune", "--with-registry-auth", "-c",
		path.Join(swarmStack.repo.path, swarmStack.composePath),
		swarmStack.name,
	})
	// To stop printing errors and
	// usage message to stdout
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	err := cmd.Execute()
	if err != nil {
		return fmt.Errorf("could not deploy stack %s: %s", swarmStack.name, err)
	}
	return nil
}
