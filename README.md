# EngineBPF
This repo offers eBPF programs used to replace the iptable functionality in Cilium.

## How to Build the Project

1. Build the Docker image:
```bash
docker build -t <namespace>/eebpf:<tag> .
```

Example:
```bash
docker build -t xiangyug/eebpf:1 .
```

2. Push the image:
```bash
docker push <namespace>/eebpf:<tag>
```

3. Update the image reference in the DaemonSet:
```bash
sed 's|xiangyug/eebpf:1|<namespace>/eebpf:<tag>|g' daemonset.yaml
```

## How to Run in a Kubernetes Cluster

1. Deploy the DaemonSet:
```bash
kubectl apply -f daemonset.yaml
```

2. Select the eebpf pod on the node of interest:
```bash
kubectl get pods -l k8s-app=eebpf -o wide --no-headers | awk '{print $1"   "$7}'
```

3. Exec into the pod:
```bash
kubectl exec -it <eebpf-pod-name> -- /bin/bash
```

4. Create or edit the configuration file:
```bash
cd src && vim conf.json
```

5. Run the tool:
```bash
python3 tcvethCilium.py --config conf.json &
```

The image also includes the `bpftool` binary, which can be used directly inside the container.
