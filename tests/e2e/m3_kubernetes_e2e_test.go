//go:build m3e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const e2eNamespace = "oncache-e2e"

func TestM3KubernetesE2E(t *testing.T) {
	if os.Getenv("ONCACHE_M3_E2E") != "1" {
		t.Skip("set ONCACHE_M3_E2E=1 to run the two-node Kubernetes E2E")
	}
	nodeA := requiredEnv(t, "ONCACHE_M3_E2E_NODE_A")
	nodeB := requiredEnv(t, "ONCACHE_M3_E2E_NODE_B")
	image := requiredEnv(t, "ONCACHE_M3_E2E_IMAGE")
	chart := getenv("ONCACHE_M3_E2E_CHART", "charts/oncache")
	evidence := getenv("ONCACHE_M3_E2E_EVIDENCE", filepath.Join(os.TempDir(), "oncache-m3-e2e"))
	if err := os.MkdirAll(evidence, 0750); err != nil {
		t.Fatal(err)
	}
	if err := assertNodesReady(nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join("tests", "e2e", "fixtures.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest = bytes.ReplaceAll(manifest, []byte("NODE_A"), []byte(nodeA))
	manifest = bytes.ReplaceAll(manifest, []byte("NODE_B"), []byte(nodeB))
	applyManifest(t, manifest)
	if cleanup := os.Getenv("ONCACHE_M3_E2E_CLEANUP") == "1"; cleanup {
		t.Cleanup(func() { _, _ = run("kubectl", "delete", "namespace", e2eNamespace, "--ignore-not-found=true") })
	}
	repository, tag := splitImage(image)
	_, err = run("helm", "upgrade", "--install", "oncache-e2e", chart, "--namespace", "kube-system", "--set", "image.repository="+repository, "--set", "image.tag="+tag, "--set", "agent.installationID=m3-e2e")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "status", "daemonset/oncache-e2e-oncache", "--timeout=180s"); err != nil {
		t.Fatal(err)
	}
	waitPod(t, "pod-a")
	waitPod(t, "pod-b")
	captureEvidence(t, evidence)
	podBIP := mustOutput(t, "kubectl", "-n", e2eNamespace, "get", "pod", "pod-b", "-o", "jsonpath={.status.podIP}")
	if _, err := run("kubectl", "-n", e2eNamespace, "exec", "pod-a", "--", "ping", "-c", "3", "-W", "2", podBIP); err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", e2eNamespace, "delete", "pod", "pod-b", "--wait=true"); err != nil {
		t.Fatal(err)
	}
	applyManifest(t, manifest)
	waitPod(t, "pod-b")
	captureEvidence(t, evidence)
}

func assertNodesReady(nodes ...string) error {
	for _, node := range nodes {
		if _, err := run("kubectl", "wait", "--for=condition=Ready", "node/"+node, "--timeout=60s"); err != nil {
			return err
		}
	}
	return nil
}

func applyManifest(t *testing.T, manifest []byte) {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(manifest)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kubectl apply: %v: %s", err, output)
	}
}

func waitPod(t *testing.T, name string) {
	t.Helper()
	if _, err := run("kubectl", "-n", e2eNamespace, "wait", "--for=condition=Ready", "pod/"+name, "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
}

func captureEvidence(t *testing.T, dir string) {
	t.Helper()
	artifacts := map[string][]string{
		"nodes.txt":     {"kubectl", "get", "nodes", "-o", "wide"},
		"pods.txt":      {"kubectl", "-n", e2eNamespace, "get", "pods", "-o", "wide"},
		"daemonset.txt": {"kubectl", "-n", "kube-system", "get", "daemonset", "oncache-e2e-oncache", "-o", "yaml"},
	}
	for name, args := range artifacts {
		output, err := run(args[0], args[1:]...)
		if writeErr := os.WriteFile(filepath.Join(dir, name), []byte(output), 0600); err != nil || writeErr != nil {
			t.Logf("evidence %s unavailable: command=%v err=%v write=%v", name, args, err, writeErr)
		}
	}
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s %v: %w: %s", name, args, err, output)
	}
	return strings.TrimSpace(string(output)), nil
}

func mustOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := run(name, args...)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func splitImage(image string) (string, string) {
	index := strings.LastIndex(image, ":")
	if index < strings.LastIndex(image, "/") {
		return image, "dev"
	}
	return image[:index], image[index+1:]
}
