# Kubernetes Dashboard Operator

## Description

Dashboard is a web-based Kubernetes user interface. You can use Dashboard to deploy containerized
applications to a Kubernetes cluster, troubleshoot your containerized application, and manage the
cluster resources. You can use Dashboard to get an overview of applications running on your
cluster, as well as for creating or modifying individual Kubernetes resources (such as Deployments,
Jobs, DaemonSets, etc). For example, you can scale a Deployment, initiate a rolling update, restart
a pod or deploy new applications using a deploy wizard.

This repository contains a [Juju](https://juju.is/) Charm for deploying the Kubernetes Dashboard.

## Usage

The Kubernetes Dashboard Operator may be deployed using the Juju command line as in

```sh
$ juju add-model dashboard
$ juju --trust deploy kubernetes-dashboard
```

## Accessing the Dashboard

The Kubernetes dashboard can be accessed via it's service cluster IP, or depending on your setup,
its pod IP.

If you deploy and allow the Kubernetes Dashboard to generate its own, self-signed certificate, the
certificate will be valid for the service cluster IP, its pod IP and its DNS name in the cluster.

For example, if you deploy into a model named `dashboard`, you'll be able to access the dashboard
at: https://kubernetes-dashboard-0.dashboard.svc.cluster.local.

## OCI Images

The charm requires the use of two OCI images, one for the dashboard, and one for the metrics
scaper.

- The dashboard image is [kubernetesui/dashboard:v2.4.0](https://hub.docker.com/r/kubernetesui/dashboard)
- The metrics scraper image is
  [kubernetesui/metrics-scraper:v1.0.7](https://hub.docker.com/r/kubernetesui/metrics-scraper)
