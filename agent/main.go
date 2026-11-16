package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const serverURLEnv = "PERSISTGUARD_AGENT_SERVER_URL"

var agentVersion = "dev"

func parseHTTPSURL(value, setting string) (*url.URL, error) {
	server, err := url.Parse(strings.TrimSpace(value))
	if err != nil || server.Scheme != "https" || server.Hostname() == "" ||
		server.User != nil || server.RawQuery != "" || server.ForceQuery || strings.Contains(value, "#") {
		return nil, fmt.Errorf("%s must be an HTTPS URL without credentials, query, or fragment", setting)
	}
	if port := server.Port(); port != "" {
		if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
			return nil, fmt.Errorf("%s contains an invalid port", setting)
		}
	}
	return server, nil
}

func run(ctx context.Context, args []string, input io.Reader, output, errors io.Writer) int {
	flags := flag.NewFlagSet("persistguard-agent", flag.ContinueOnError)
	flags.SetOutput(errors)
	showVersion := flags.Bool("version", false, "print the agent version and exit")
	checkConfig := flags.Bool("check-config", false, "validate configuration and exit")
	generateCSR := flags.Bool("generate-csr", false, "write a device certificate signing request to stdout")
	enroll := flags.Bool("enroll", false, "read an invitation token from stdin and register this device")
	enrollmentURL := flags.String("enrollment-url", "", "HTTPS base URL of the enrollment API")
	organizationID := flags.String("organization-id", "", "organization ID from the enrollment invitation")
	startupInventory := flags.Bool("startup-inventory", false, "read Windows startup Registry values and print a local JSON inventory")
	scheduledTasksInventory := flags.Bool("scheduled-tasks-inventory", false, "read Windows Scheduled Tasks and print a local JSON inventory")
	servicesInventory := flags.Bool("services-inventory", false, "read Windows services and print a local JSON inventory")
	windowsInventory := flags.Bool("windows-inventory", false, "run all Windows collectors and print a combined local JSON report")
	checkIdentity := flags.Bool("check-identity", false, "authenticate to the gateway once and print the assigned identity")
	heartbeat := flags.Bool("heartbeat", false, "send one authenticated heartbeat to the gateway")
	pollJob := flags.Bool("poll-job", false, "poll the gateway once for this device's inventory job")
	runInventoryJob := flags.Bool("run-inventory-job", false, "run and upload one assigned Windows inventory job")
	watchInventoryJobs := flags.Bool("watch-inventory-jobs", false, "poll for and run assigned Windows inventory jobs until stopped")
	windowsService := flags.Bool("windows-service", false, "run --watch-inventory-jobs under Windows Service Control Manager")
	serviceLog := flags.String("service-log", "", "optional log file for Windows service receipts and diagnostics")
	gatewayURL := flags.String("gateway-url", "", "HTTPS gateway base URL (overrides "+serverURLEnv+")")
	pollInterval := flags.Duration("poll-interval", 30*time.Second, "delay between polls in --watch-inventory-jobs mode")
	renewCertificate := flags.Bool("renew-certificate", false, "request a replacement device certificate and write its PEM to stdout")
	confirmCertificate := flags.Bool("confirm-certificate", false, "confirm a replacement certificate and retire its predecessor")
	deviceKey := flags.String("device-key", "", "path to the Windows DPAPI-protected device key")
	clientCert := flags.String("client-cert", "", "path to the issued device certificate PEM file")
	serverCA := flags.String("server-ca", "", "optional PEM CA bundle for verifying the server certificate")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errors, "persistguard-agent takes no positional arguments")
		return 2
	}
	if *showVersion {
		if flags.NFlag() != 1 {
			fmt.Fprintln(errors, "run --version on its own")
			return 2
		}
		fmt.Fprintln(output, agentVersion)
		return 0
	}
	intervalSpecified := false
	flags.Visit(func(option *flag.Flag) {
		if option.Name == "poll-interval" {
			intervalSpecified = true
		}
	})
	if intervalSpecified && (!*watchInventoryJobs || *pollInterval <= 0) {
		fmt.Fprintln(errors, "--poll-interval must be positive and requires --watch-inventory-jobs")
		return 2
	}
	if (*windowsService && !*watchInventoryJobs) || (*serviceLog != "" && !*windowsService) {
		fmt.Fprintln(errors, "--windows-service requires --watch-inventory-jobs, and --service-log requires --windows-service")
		return 2
	}
	if !*enroll && (*enrollmentURL != "" || *organizationID != "") {
		fmt.Fprintln(errors, "--enrollment-url and --organization-id require --enroll")
		return 2
	}
	operation := ""
	for _, command := range []struct {
		enabled bool
		path    string
	}{
		{*checkIdentity, "identity"}, {*heartbeat, "heartbeat"}, {*pollJob, "scan-jobs/poll"},
		{*runInventoryJob, "scan-jobs/run"},
		{*watchInventoryJobs, "scan-jobs/watch"},
		{*renewCertificate, "certificate/renew"}, {*confirmCertificate, "certificate/confirm"},
	} {
		if command.enabled {
			if operation != "" {
				fmt.Fprintln(errors, "select one gateway command per run")
				return 2
			}
			operation = command.path
		}
	}
	usesCertificate := operation != ""
	if *gatewayURL != "" && !usesCertificate {
		fmt.Fprintln(errors, "--gateway-url requires a gateway command")
		return 2
	}
	var collect func(context.Context, io.Writer) error
	for _, command := range []struct {
		enabled bool
		run     func(context.Context, io.Writer) error
	}{
		{*startupInventory, writeStartupInventory}, {*scheduledTasksInventory, writeScheduledTasksInventory},
		{*servicesInventory, writeServicesInventory}, {*windowsInventory, writeWindowsInventory},
	} {
		if command.enabled {
			if collect != nil {
				fmt.Fprintln(errors, "run one inventory command on its own")
				return 2
			}
			collect = command.run
		}
	}
	if collect != nil {
		if *generateCSR || *enroll || *checkConfig || usesCertificate ||
			*deviceKey != "" || *clientCert != "" || *serverCA != "" {
			fmt.Fprintln(errors, "run one inventory command on its own")
			return 2
		}
		if err := collect(ctx, output); err != nil {
			fmt.Fprintln(errors, err)
			return 1
		}
		return 0
	}
	if *generateCSR {
		if *enroll || *checkConfig || operation != "" || *clientCert != "" || *serverCA != "" || strings.TrimSpace(*deviceKey) == "" {
			fmt.Fprintln(errors, "use --generate-csr with --device-key only")
			return 2
		}
		if err := writeDeviceCSR(*deviceKey, output); err != nil {
			fmt.Fprintln(errors, err)
			return 1
		}
		return 0
	}
	if *enroll {
		organization := strings.ToLower(strings.TrimSpace(*organizationID))
		if *checkConfig || usesCertificate || *clientCert != "" || !uuidText.MatchString(organization) || strings.TrimSpace(*deviceKey) == "" {
			fmt.Fprintln(errors, "use --enroll with --enrollment-url, --organization-id, --device-key, and optionally --server-ca")
			return 2
		}
		server, err := parseHTTPSURL(*enrollmentURL, "--enrollment-url")
		if err != nil {
			fmt.Fprintln(errors, err)
			return 2
		}
		if runtime.GOOS != "windows" {
			fmt.Fprintln(errors, "device enrollment requires Windows")
			return 1
		}
		if err := enrollDevice(ctx, server, organization, *deviceKey, *serverCA, input, output); err != nil {
			fmt.Fprintln(errors, err)
			return 1
		}
		return 0
	}
	if usesCertificate && (*checkConfig || strings.TrimSpace(*deviceKey) == "" || strings.TrimSpace(*clientCert) == "") {
		fmt.Fprintln(errors, "gateway commands require --device-key and --client-cert, and optionally --server-ca")
		return 2
	}
	if !usesCertificate && (*deviceKey != "" || *clientCert != "" || *serverCA != "") {
		fmt.Fprintln(errors, "certificate and key flags require --generate-csr, --enroll, or a gateway command")
		return 2
	}

	serverValue, serverSetting := os.Getenv(serverURLEnv), serverURLEnv
	if *gatewayURL != "" {
		serverValue, serverSetting = *gatewayURL, "--gateway-url"
	}
	server, err := parseHTTPSURL(serverValue, serverSetting)
	if err != nil {
		fmt.Fprintln(errors, err)
		return 2
	}
	if usesCertificate {
		if (*runInventoryJob || *watchInventoryJobs) && runtime.GOOS != "windows" {
			fmt.Fprintln(errors, "Windows inventory job execution requires Windows")
			return 1
		}
		if *watchInventoryJobs {
			watch := func(ctx context.Context, receipts, diagnostics io.Writer) error {
				runOne := func(ctx context.Context, receipt io.Writer) error {
					rotation := func(path, operation string, response io.Writer) error {
						return runGatewayCommand(ctx, server, *deviceKey, path, *serverCA, operation, response)
					}
					if err := maintainDeviceCertificate(*clientCert, time.Now(), rotation); err != nil && ctx.Err() == nil {
						fmt.Fprintf(diagnostics, "Automatic certificate renewal: %v. Will retry on the next poll.\n", err)
					}
					return runGatewayCommand(ctx, server, *deviceKey, *clientCert, *serverCA, "scan-jobs/run", receipt)
				}
				watchCtx, cancel := context.WithCancel(ctx)
				heartbeatDone := make(chan struct{})
				go func() {
					defer close(heartbeatDone)
					sendHeartbeat := func(ctx context.Context) error {
						return runGatewayCommand(ctx, server, *deviceKey, *clientCert, *serverCA, "heartbeat", io.Discard)
					}
					watchHeartbeat(watchCtx, 30*time.Second, sendHeartbeat, diagnostics)
				}()
				err := watchInventory(watchCtx, *pollInterval, runOne, receipts, diagnostics)
				cancel()
				<-heartbeatDone
				return err
			}
			var err error
			if *windowsService {
				err = runWindowsService(ctx, *serviceLog, watch)
			} else {
				err = watch(ctx, output, errors)
			}
			if err != nil {
				fmt.Fprintln(errors, err)
				return 1
			}
			return 0
		}
		if err := runGatewayCommand(ctx, server, *deviceKey, *clientCert, *serverCA, operation, output); err != nil {
			fmt.Fprintln(errors, err)
			return 1
		}
		return 0
	}
	if *checkConfig {
		fmt.Fprintln(output, "Agent configuration is valid.")
		return 0
	}

	fmt.Fprintln(output, "PersistGuard agent started. Waiting for shutdown.")
	<-ctx.Done()
	fmt.Fprintln(output, "PersistGuard agent stopped.")
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
