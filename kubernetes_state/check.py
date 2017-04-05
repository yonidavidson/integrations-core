# (C) Datadog, Inc. 2016
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

from checks import CheckException
from utils.prometheus.base_check import PrometheusCheck


class KubernetesState(PrometheusCheck):
    def __init__(self, name, init_config, agentConfig, instances):
        super(KubernetesState, self).__init__(name, init_config, agentConfig, instances)
        self.NAMESPACE = 'kubernetes_state'
        # Original camelcase keys have already been converted to lowercase.
        self.pod_phase_to_status = {
            'pending':   self.WARNING,
            'running':   self.OK,
            'succeeded': self.OK,
            'failed':    self.CRITICAL,
            # Rely on lookup default value
            # 'unknown':   AgentCheck.UNKNOWN
        }

        # these metrics will be extracted with all their labels and reported as-is with their corresponding metric name
        self.metric_to_gauge = {
            # message.metric: datadog metric name
            'kube_node_status_capacity_cpu_cores': self.NAMESPACE + '.node.cpu_capacity',
            'kube_node_status_capacity_memory_bytes': self.NAMESPACE + '.node.memory_capacity',
            'kube_node_status_capacity_pods': self.NAMESPACE + '.node.pods_capacity',
            'kube_node_status_allocatable_cpu_cores': self.NAMESPACE + '.node.cpu_allocatable',
            'kube_node_status_allocatable_memory_bytes': self.NAMESPACE + '.node.memory_allocatable',
            'kube_node_status_allocatable_pods': self.NAMESPACE + '.node.pods_allocatable',
            'kube_deployment_status_replicas_available': self.NAMESPACE + '.deployment.replicas_available',
            'kube_deployment_status_replicas_unavailable': self.NAMESPACE + '.deployment.replicas_unavailable',
            'kube_deployment_status_replicas_updated': self.NAMESPACE + '.deployment.replicas_updated',
            'kube_deployment_spec_replicas': self.NAMESPACE + '.deployment.replicas_desired',
            'kube_pod_container_resource_requests_cpu_cores': self.NAMESPACE + '.container.cpu_requested',
            'kube_pod_container_resource_requests_memory_bytes': self.NAMESPACE + '.container.memory_requested',
            'kube_pod_container_limits_cpu_cores': self.NAMESPACE + '.container.cpu_limit',
            'kube_pod_container_limits_memory_bytes': self.NAMESPACE + '.container.memory_limit',
            'kube_pod_container_status_restarts': self.NAMESPACE + '.container.restarts'
        }

    def check(self, instance):
        kube_state_url = instance.get('kube_state_url')
        tags = instance.get('tags', [])
        tags = set(tags)
        if kube_state_url is None:
            raise CheckException("Unable to find kube_state_url in config file.")

        try:
            payload = self.perform_protobuf_query(kube_state_url)
            msg = "Got a payload of size {} from Kube State API at url:{}".format(len(payload), kube_state_url)
            self.log.debug(msg)
            self.process(payload, tags=tags)
        except Exception as e:
            self.log.error("Unable to retrieve metrics from Kube State API: {}".format(e))

    # TODO: implement kube_pod_container_status_ready
    # TODO: implement kube_pod_container_status_running
    # TODO: implement kube_pod_container_status_terminated
    # TODO: implement kube_pod_container_status_waiting

    # TODO: implement kube_pod_info
    # TODO: implement kube_pod_status_ready
    # TODO: implement kube_pod_status_scheduled

    # Labels attached: namespace, pod, phase=Pending|Running|Succeeded|Failed|Unknown
    # The phase gets not passed through; rather, it becomes the service check suffix.
    def kube_pod_status_phase(self, message, **kwargs):
        """ Phase a pod is in. """
        check_basename = self.NAMESPACE + '.pod.phase.'
        for metric in message.metric:
            # The gauge value is always 1, no point in fetching it.
            phase = ''
            tags = []
            for label in metric.label:
                if label.name == 'phase':
                    phase = label.value.lower()
                else:
                    tags.append('{}:{}'.format(label.name, label.value))
            #TODO: add deployment/replicaset?
            status = self.pod_phase_to_status.get(phase, self.UNKNOWN)
            self.service_check(check_basename + phase, status, tags=tags)

    def kube_node_status_ready(self, message, **kwargs):
        """ The ready status of a cluster node. """
        service_check_name = self.NAMESPACE + '.node.ready'
        for metric in message.metric:
            name, val = self._eval_metric_condition(metric)
            tags = ['node:{}'.format(self._extract_label_value("node", metric.label))]
            if name == 'true' and val:
                self.service_check(service_check_name, self.OK, tags=tags)
            elif name == 'false' and val:
                self.service_check(service_check_name, self.CRITICAL, tags=tags)
            elif name == 'unknown' and val:
                self.service_check(service_check_name, self.UNKNOWN, tags=tags)

    def kube_node_status_out_of_disk(self, message, **kwargs):
        """ Whether the node is out of disk space. """
        service_check_name = self.NAMESPACE + '.node.out_of_disk'
        for metric in message.metric:
            name, val = self._eval_metric_condition(metric)
            tags = ['node:{}'.format(self._extract_label_value("node", metric.label))]
            if name == 'true' and val:
                self.service_check(service_check_name, self.CRITICAL, tags=tags)
            elif name == 'false' and val:
                self.service_check(service_check_name, self.OK, tags=tags)
            elif name == 'unknown' and val:
                self.service_check(service_check_name, self.UNKNOWN, tags=tags)

    def kube_node_spec_unschedulable(self, message, **kwargs):
        """ Whether a node can schedule new pods. """
        metric_name = self.NAMESPACE + '.node.status'
        statuses = ('schedulable', 'unschedulable')
        if message.type < len(self.METRIC_TYPES):
            for metric in message.metric:
                tags = ['{}:{}'.format(label.name, label.value) for label in metric.label]
                status = statuses[int(getattr(metric, self.METRIC_TYPES[message.type]).value)]  # value can be 0 or 1
                tags.append('status:{}'.format(status))
                self.gauge(metric_name, 1, tags)  # metric value is always one, value is on the tags
        else:
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
