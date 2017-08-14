# (C) Datadog, Inc. 2016-2017
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

# stdlib
import calendar
import re
import time
from collections import defaultdict

# project
from checks import AgentCheck, CheckException
from checks.prometheus_check import PrometheusCheck
from config import _is_affirmative
from utils.dockerutil import DockerUtil
from utils.kubernetes.kubeutil import KubeUtil
from utils.service_discovery.sd_backend import get_sd_backend

METRIC_TYPES = ['counter', 'gauge', 'summary']

DEFAULT_COLLECT_EVENTS = False
DEFAULT_SERVICE_EVENT_FREQ = 5 * 60  # seconds
DEFAULT_NAMESPACES = ['default']
EVENT_TYPE = 'kubernetes'

GAUGE = AgentCheck.gauge
RATE = AgentCheck.rate

# if histograms are used instead of exact metrics
# HISTO and HISTORATE are used instead of gauge and rate
# and they exclude the container_name tag, greatly decreasing the
# tag count, and making the drop-down menu in the app
# much quicker to load for the impacted metrics.
DEFAULT_USE_HISTOGRAM = False
HISTORATE = AgentCheck.generate_historate_func(["container_name"])
HISTO = AgentCheck.generate_histogram_func(["container_name"])
FUNC_MAP = {
    GAUGE: {True: HISTO, False: GAUGE},
    RATE: {True: HISTORATE, False: RATE}
}


class KubeletCheck(PrometheusCheck):
    """
    Collect Kubelet metrics
    TODO:
    - handle custom cAdvisor metrics (see _update_metrics chain)
    - merge with kubernetes check
    - can we do major check version & break retro-comp?
    """
    def __init__(self, name, init_config, agentConfig, instances=None):
        super(KubeletCheck, self).__init__(name, init_config, agentConfig, instances)
        self.NAMESPACE = 'kubernetes'

        if instances is not None and len(instances) > 1:
            raise Exception('Kubernetes check only supports one configured instance.')
        inst = instances[0] if instances else None

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

        # auto discovery
        if agentConfig.get('service_discovery') and \
           agentConfig.get('service_discovery_backend') == 'docker':
            self._sd_backend = get_sd_backend(agentConfig)
        else:
            self._sd_backend = None

        # event collection & service tagging
        self.k8s_namespace_regexp = None
        if inst:
            regexp = inst.get('namespace_name_regexp', None)
            if regexp:
                try:
                    self.k8s_namespace_regexp = re.compile(regexp)
                except re.error as ex:
                    self.log.warning('Invalid regexp for "namespace_name_regexp" in configuration (ignoring regexp): %s' % str(ex))

            self._collect_events = _is_affirmative(inst.get('collect_events', DEFAULT_COLLECT_EVENTS))
            if self._collect_events:
                self.event_retriever = self.kubeutil.get_event_retriever()
            elif self.kubeutil.collect_service_tag:
                # Only fetch service and pod events for service mapping
                event_delay = inst.get('service_tag_update_freq', DEFAULT_SERVICE_EVENT_FREQ)
                self.event_retriever = self.kubeutil.get_event_retriever(kinds=['Service', 'Pod'],
                                                                         delay=event_delay)
            else:
                self.event_retriever = None
        else:
            self._collect_events = None
            self.event_retriever = None

    def check(self, instance):
        self.use_histogram = _is_affirmative(instance.get('use_histogram', DEFAULT_USE_HISTOGRAM))
        self.publish_rate = FUNC_MAP[RATE][self.use_histogram]
        self.publish_gauge = FUNC_MAP[GAUGE][self.use_histogram]

        endpoint = instance.get('metrics_endpoint')
        if endpoint is None:
            raise CheckException("Unable to find metrics_endpoint in config file.")

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
            pod_list = self.kubeutil.retrieve_pods_list()
        except:
            pod_list = None

        instance_tags = instance.get('tags', [])
        self._report_node_metrics(instance_tags)
        self._perform_kubelet_check(instance_tags)
        self._report_pods_running(pod_list, instance_tags)
        self.process(endpoint, send_histograms_buckets=send_buckets, instance=instance)

        # events
        if self.event_retriever is not None:
            try:
                events = self.event_retriever.get_event_array()
                changed_cids = self.kubeutil.process_events(events, podlist=pod_list)
                if (changed_cids and self._sd_backend):
                    self._sd_backend.update_checks(changed_cids)
                if events and self._collect_events:
                    self._update_kube_events(instance, events)
            except Exception as ex:
                self.log.error("Event collection failed: %s" % str(ex))

    def _report_node_metrics(self, instance_tags):
        machine_info = self.kubeutil.retrieve_machine_info()
        num_cores = machine_info.get('num_cores', 0)
        memory_capacity = machine_info.get('memory_capacity', 0)
        pod_capacity = machine_info.get('pods')

        tags = instance_tags
        self.publish_gauge(self, self.NAMESPACE + '.cpu.capacity', float(num_cores), tags)
        self.publish_gauge(self, self.NAMESPACE + '.memory.capacity', float(memory_capacity), tags)

        # extracted from the apiserver, may be missing
        if pod_capacity:
            self.publish_gauge(self, self.NAMESPACE + '.pods.capacity', float(pod_capacity), tags)
        for res, val in machine_info.get('allocatable', {}).iteritems():
            try:
                m_name = self.NAMESPACE + '.{}.allocatable'.format(res)
                if res == 'memory':
                    val = self.kubeutil.parse_quantity(val)
                self.publish_gauge(self, m_name, float(val), tags)
            except Exception as ex:
                self.log.warning("Failed to report metric %s. Err: %s" % (m_name, str(ex)))

    def _perform_kubelet_check(self, instance_tags):
        """Runs local service checks"""
        service_check_base = self.NAMESPACE + '.kubelet.check'
        is_ok = True
        url = self.kubeutil.kube_health_url

        try:
            req = self.kubeutil.perform_kubelet_query(url)
            for line in req.iter_lines():
                # avoid noise; this check is expected to fail since we override the container hostname
                if line.find('hostname') != -1:
                    continue

                matches = re.match(r'\[(.)\]([^\s]+) (.*)?', line)
                if not matches or len(matches.groups()) < 2:
                    continue

                service_check_name = service_check_base + '.' + matches.group(2)
                status = matches.group(1)
                if status == '+':
                    self.service_check(service_check_name, AgentCheck.OK, tags=instance_tags)
                else:
                    self.service_check(service_check_name, AgentCheck.CRITICAL, tags=instance_tags)
                    is_ok = False

        except Exception as e:
            self.log.warning('kubelet check %s failed: %s' % (url, str(e)))
            self.service_check(service_check_base, AgentCheck.CRITICAL,
                               message='Kubelet check %s failed: %s' % (url, str(e)), tags=instance_tags)
        else:
            if is_ok:
                self.service_check(service_check_base, AgentCheck.OK, tags=instance_tags)
            else:
                self.service_check(service_check_base, AgentCheck.CRITICAL, tags=instance_tags)

    def _report_pods_running(self, pods, instance_tags):
        """
        Reports the number of running pods on this node
        tagged by service and creator.
        """
        tags_map = defaultdict(int)
        for pod in pods['items']:
            pod_meta = pod.get('metadata', {})
            pod_tags = []
            pod_tags += instance_tags
            pod_tags += self.kubeutil.get_pod_creator_tags(pod_meta)
            if 'namespace' in pod_meta:
                pod_tags.append('kube_namespace:%s' % pod_meta['namespace'])
            if 'component' in pod_meta.get('labels', {}):
                pod_tags.append('kube_component:%s' % pod_meta['labels']['component'])
            if self.kubeutil.collect_service_tag:
                services = self.kubeutil.match_services_for_pod(pod_meta)
                if isinstance(services, list):
                    for service in services:
                        pod_tags.append('kube_service:%s' % service)

            tags_map[frozenset(pod_tags)] += 1

        for tags, count in tags_map.iteritems():
            tags = list(tags)
            self.publish_gauge(self, self.NAMESPACE + '.pods.running', count, tags)

    def container_cpu_usage_seconds_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.cpu.usage.total'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_container_metric(metric):
                tags = self.kubeutil.extract_metric_tags(metric.label)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.publish_rate(self, metric_name, val, tags)

    def _process_usage_metric(self, m_name, message, cache):
        """
        Takes a metrics message, a metric name, and a cache dict where it will store
        container_name --> (value, tags) so that _process_limit_metric can compute usage_pct
        it also submit said value and tags as a gauge.
        """
        # track containers that still exist in the cache
        seen_keys = {k: False for k in cache}
        for metric in message.metric:
            if self._is_container_metric(metric):
                tags = self.kubeutil.extract_metric_tags(metric.label)
                c_name = None
                for t in tags:
                    if t.split(':', 1)[0] == 'container_name':
                        c_name = t.split(':', 1)[1]
                        break
                val = getattr(metric, METRIC_TYPES[message.type]).value
                if c_name:
                    cache[c_name] = (val, tags)
                    seen_keys[c_name] = True
                self.publish_gauge(self, m_name, val, tags)

        # purge the cache
        for k, seen in seen_keys.iteritems():
            if not seen:
                del cache[k]

    def _process_limit_metric(self, m_name, message, cache, pct_m_name=None):
        """
        Reports limit metrics if m_name is not an empty string,
        and optionally checks in the given cache if there's a usage
        for each metric in the message and reports the usage_pct
        """
        for metric in message.metric:
            if self._is_container_metric(metric):
                limit = getattr(metric, METRIC_TYPES[message.type]).value
                tags = self.kubeutil.extract_metric_tags(metric.label)

                if m_name:
                    self.publish_gauge(self, m_name, limit, tags)

                if pct_m_name and limit > 0:
                    usage = None
                    c_name = ''
                    for lbl in metric.label:
                        if lbl.name == 'name':
                            c_name = lbl.value
                            usage, tags = cache.get(c_name, (None, None))
                            break
                    if usage:
                        self.publish_gauge(self, pct_m_name, float(usage/float(limit)), tags)
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
                        self.publish_gauge(self, metric_name, float(usage/float(limit)), tags)
                else:
                    self.log.debug("No mem usage found for container %s, skipping usage_pct for now." % c_name)

    def container_network_receive_bytes_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.rx_bytes'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_pod_metric(metric):
                tags = self.kubeutil.extract_metric_tags(metric.label)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.publish_rate(self, metric_name, val, tags)

    def container_network_transmit_bytes_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.tx_bytes'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_pod_metric(metric):
                tags = self.kubeutil.extract_metric_tags(metric.label)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.publish_rate(self, metric_name, val, tags)

    def container_network_receive_errors_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.rx_errors'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_pod_metric(metric):
                tags = self.kubeutil.extract_metric_tags(metric.label)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.publish_rate(self, metric_name, val, tags)

    def container_network_transmit_errors_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.tx_errors'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_pod_metric(metric):
                tags = self.kubeutil.extract_metric_tags(metric.label)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.publish_rate(self, metric_name, val, tags)

    def _update_kube_events(self, instance, event_items):
        """Process kubernetes events"""
        node_ip, node_name = self.kubeutil.get_node_info()
        self.log.debug('Processing events on {} [{}]'.format(node_name, node_ip))

        k8s_namespaces = self.kubeutil.get_namespaces(instance, self.k8s_namespace_regexp)
        for event in event_items:
            event_ts = calendar.timegm(time.strptime(event.get('lastTimestamp'), '%Y-%m-%dT%H:%M:%SZ'))
            involved_obj = event.get('involvedObject', {})

            # filter events by white listed namespaces (empty namespace belong to the 'default' one)
            if involved_obj.get('namespace', 'default') not in k8s_namespaces:
                continue

            tags = self.kubeutil.extract_event_tags(event)
            tags.extend(instance.get('tags', []))

            title = '{} {} on {}'.format(involved_obj.get('name'), event.get('reason'), node_name)
            message = event.get('message')
            source = event.get('source')
            if source:
                message += '\nSource: {} {}\n'.format(source.get('component', ''), source.get('host', ''))
            msg_body = "%%%\n{}\n```\n{}\n```\n%%%".format(title, message)
            dd_event = {
                'timestamp': event_ts,
                'host': node_ip,
                'event_type': EVENT_TYPE,
                'msg_title': title,
                'msg_text': msg_body,
                'source_type_name': EVENT_TYPE,
                'event_object': 'kubernetes:{}'.format(involved_obj.get('name')),
                'tags': tags,
            }
            self.event(dd_event)
