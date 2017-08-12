# (C) Datadog, Inc. 2016-2017
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

# stdlib
from collections import defaultdict

# project
from checks import AgentCheck, CheckException
from checks.prometheus_check import PrometheusCheck
from config import _is_affirmative
from utils.dockerutil import DockerUtil
from utils.kubernetes.kubeutil import KubeUtil

METRIC_TYPES = ['counter', 'gauge', 'summary']

DEFAULT_USE_HISTOGRAM = False
GAUGE = AgentCheck.gauge
RATE = AgentCheck.rate
HISTORATE = AgentCheck.generate_historate_func(["container_name"])
HISTO = AgentCheck.generate_histogram_func(["container_name"])
FUNC_MAP = {
    GAUGE: {True: HISTO, False: GAUGE},
    RATE: {True: HISTORATE, False: RATE}
}

CONTAINER_LABELS = [
    'container_name',  # kubernetes container name
    'id',  # cgroup path
    'image',
    'name',  # docker container name
    'namespace',  # kubernetes namespace
    'pod_name'
]

CONTAINER_LABELS_TO_TAGS = {
    'container_name': 'kube_container_name',
    'namespace': 'kube_namespace',
    'pod_name': 'pod_name',
    'name': 'container_name',
    'image': 'container_image',
}


class KubeletCheck(PrometheusCheck):
    """
    Collect Kubelet metrics
    """
    def __init__(self, name, init_config, agentConfig, instances=None):
        super(KubeletCheck, self).__init__(name, init_config, agentConfig, instances)
        self.NAMESPACE = 'kubernetes'
        self.dockerutil = DockerUtil()
        try:
            self.kubeutil = KubeUtil()
        except Exception as ex:
            raise CheckException("Couldn't instantiate the Kubernetes client. Error: %s" % str(ex))

        self.metrics_mapper = {
            'kubelet_runtime_operations_errors': 'kubelet.runtime.errors',
        }
        self.ignore_metrics = {}

        # these are filled by container_<metric-name>_usage_<metric-unit>
        # and container_<metric-name>_limit_<metric-unit> reads it to compute <metric-name>usage_pct
        self.fs_usage_bytes = {}
        self.mem_usage_bytes = {}

        # pod --> tags map
        self.kube_pod_tags = {}

    def check(self, instance):
        self.use_histogram = _is_affirmative(instance.get('use_histogram', DEFAULT_USE_HISTOGRAM))
        self.publish_rate = FUNC_MAP[RATE][self.use_histogram]
        self.publish_gauge = FUNC_MAP[GAUGE][self.use_histogram]

        endpoint = instance.get('prometheus_endpoint')
        if endpoint is None:
            raise CheckException("Unable to find prometheus_endpoint in config file.")

        send_buckets = instance.get('send_histograms_buckets', True)
        # By default we send the buckets.
        if send_buckets is not None and str(send_buckets).lower() == 'false':
            send_buckets = False
        else:
            send_buckets = True

        try:
            self.kube_pod_tags = self.kubeutil.get_kube_pod_tags()
        except Exception as e:
            self.log.warning('Could not retrieve kubernetes tags: %s' % str(e))

        try:
            pods_list = self.kubeutil.retrieve_pods_list()
        except:
            pods_list = None

        self._report_pods_running(pods_list, instance.get('tags', []))
        self.process(endpoint, send_histograms_buckets=send_buckets, instance=instance)

    def _report_pods_running(self, pods, instance_tags):
        """
        Reports the number of running pods on this node
        tagged by service and creator.
        """
        tags_map = defaultdict(int)
        for pod in pods['items']:
            pod_meta = pod.get('metadata', {})
            pod_tags = instance_tags
            pod_tags += self.kubeutil.get_pod_creator_tags(pod_meta)
            if 'namespace' in pod_meta:
                pod_tags.append('kube_namespace:%s' % pod_meta['namespace'])
            if self.collect_service_tag:
                services = self.kubeutil.match_services_for_pod(pod_meta)
                if isinstance(services, list):
                    for service in services:
                        pod_tags.append('kube_service:%s' % service)

            tags_map[frozenset(pod_tags)] += 1

        for pod_tags, pod_count in tags_map.iteritems():
            tags = list(pod_tags)
            self.publish_gauge(self, self.NAMESPACE + '.pods.running', pod_count, tags)


    def _is_container_metric(self, metric):
        """
        Return whether a metric is about a container or not.
        It can be about pods, or even higher levels in the cgroup hierarchy
        and we don't want to report on that.
        """
        for l in CONTAINER_LABELS:
            if l == 'container_name':
                for ml in metric.label:
                    if ml.name == l:
                        if ml.value == 'POD':
                            return False
            elif l not in [ml.name for ml in metric.label]:
                return False
        return True

    def _is_pod_metric(self, metric):
        """
        Return whether a metric is about a pod or not.
        It can be about pods, or even higher levels in the cgroup hierarchy
        and we don't want to report on that.
        """
        for l in CONTAINER_LABELS:
            if l == 'container_name':
                for ml in metric.label:
                    if ml.name == l:
                        if ml.value == 'POD':
                            return True
        return False

    def _extract_image_tags(self, image_label):
        """Get the image tags using dockerutil"""
        tags = []
        # These extracters expect a container dict.
        # We pass them one with the only info they need
        dummy_container = {'Image': image_label}
        docker_image = self.dockerutil.image_name_extractor(dummy_container)
        image_name_array = self.dockerutil.image_tag_extractor(dummy_container, 0)
        image_tag_array = self.dockerutil.image_tag_extractor(dummy_container, 1)
        if docker_image:
            tags.append('container_image:%s' % docker_image)
        if image_name_array and len(image_name_array) > 0:
            tags.append('image_name:%s' % image_name_array[0])
        if image_tag_array and len(image_tag_array) > 0:
            tags.append('image_tag:%s' % image_tag_array[0])
        return tags

    def _extract_metric_tags(self, labels):
        tags = []
        pname, ns = None, None
        for label in labels:
            if label.name == 'image':
                tags += self._extract_image_tags(label.value)
            elif label.name == "pod_name":
                pname = label.value
            elif label.name == 'namespace':
                ns = label.value
            else:
                if label.name in CONTAINER_LABELS_TO_TAGS:
                    tags.append('{}:{}'.format(CONTAINER_LABELS_TO_TAGS[label.name], label.value))
            if pname and ns:
                tags += self.kube_pod_tags.get('{}/{}'.format(ns, pname), [])
        return tags

    def container_cpu_usage_seconds_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.cpu.usage.total'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_container_metric(metric):
                tags = self._extract_metric_tags(metric.label)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.rate(metric_name, val, tags)

    def _process_usage_metric(self, m_name, message, cache):
        """
        takes a metrics message, a metric name, and a cache dict where it will store
        container_name --> (value, tags) so that _process_limit_metric can compute usage_pct
        it also submit said value and tags as a gauge.
        """
        # track containers that still exist in the cache
        seen_keys = {k: False for k in cache.keys()}
        for metric in message.metric:
            if self._is_container_metric(metric):
                tags = self._extract_metric_tags(metric.label)
                c_name = None
                for t in tags:
                    if t.split(':', 1)[0] == 'container_name':
                        c_name = t.split(':', 1)[1]
                        break
                val = getattr(metric, METRIC_TYPES[message.type]).value
                if c_name:
                    cache[c_name] = (val, tags)
                    seen_keys[c_name] = True
                self.gauge(m_name, val, tags)

        # purge the cache
        for k, seen in seen_keys.iteritems():
            if not seen:
                del cache[k]

    def _process_limit_metric(self, m_name, message, cache, pct_m_name=None):
        """
        reports limit metrics if m_name is not an empty string,
        and optionally checks in the given cache if there's a usage
        for each metric in the message and reports the usage_pct
        """
        for metric in message.metric:
            if self._is_container_metric(metric):
                limit = getattr(metric, METRIC_TYPES[message.type]).value
                tags = self._extract_metric_tags(metric.label)

                if m_name:
                    self.gauge(m_name, limit, tags)

                if pct_m_name and limit > 0:
                    usage = None
                    c_name = ''
                    for lbl in metric.label:
                        if lbl.name == 'name':
                            c_name = lbl.value
                            usage, tags = cache.get(c_name, (None, None))
                            break
                    if usage:
                        self.gauge(pct_m_name, float(usage/float(limit)), tags)
                    else:
                        self.log.debug("No corresponding usage found for metric %s and container %s, skipping usage_pct for now." % (m_name, c_name))

    def container_fs_usage_bytes(self, message, **kwargs):
        """Number of bytes that are consumed by the container on this filesystem."""
        metric_name = self.NAMESPACE + '.filesystem.usage'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return
        self._process_usage_metric(metric_name, message, self.fs_usage_bytes)

    def container_fs_limit_bytes(self, message, **kwargs):
        """
        Number of bytes that can be consumed by the container on this filesystem.
        This method is used by container_fs_usage_bytes, it doesn't report any metric
        """
        pct_m_name = self.NAMESPACE + '.filesystem.usage_pct'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return
        self._process_limit_metric('', message, self.fs_usage_bytes, pct_m_name)

    def container_memory_usage_bytes(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.memory.usage'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return
        self._process_usage_metric(metric_name, message, self.mem_usage_bytes)

    def container_spec_memory_limit_bytes(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.memory.limits'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_container_metric(metric):
                usage = None
                c_name = ''
                for lbl in metric.label:
                    if lbl.name == 'name':
                        c_name = lbl.value
                        usage, tags = self.mem_usage_bytes.get(c_name, (None, None))

                if usage and tags:
                    limit = getattr(metric, METRIC_TYPES[message.type]).value
                    if limit > 0:
                        self.gauge(metric_name, float(usage/float(limit)), tags)
                else:
                    self.log.debug("No mem usage found for container %s, skipping usage_pct for now." % c_name)

    def container_network_receive_bytes_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.rx_bytes'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_pod_metric(metric):
                tags = self._extract_metric_tags(metric.label)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.rate(metric_name, val, tags)

    def container_network_transmit_bytes_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.tx_bytes'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_pod_metric(metric):
                tags = self._extract_metric_tags(metric.label)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.rate(metric_name, val, tags)

    def container_network_receive_errors_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.rx_errors'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_pod_metric(metric):
                tags = self._extract_metric_tags(metric.label)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.rate(metric_name, val, tags)

    def container_network_transmit_errors_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.tx_errors'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_pod_metric(metric):
                tags = self._extract_metric_tags(metric.label)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.rate(metric_name, val, tags)
