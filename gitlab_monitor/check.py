from checks import CheckException
from checks.prometheus_check import PrometheusCheck

EVENT_TYPE = SOURCE_TYPE_NAME = 'gitlab'

class GitlabMonitorCheck(PrometheusCheck):
    """
    Collect kube-dns metrics from Prometheus
    """
    def __init__(self, name, init_config, agentConfig, instances=None):
        super(GitlabMonitorCheck, self).__init__(name, init_config, agentConfig, instances)
        self.NAMESPACE = 'gitlab'

        # See https://gitlab.com/gitlab-org/gitlab-monitor
        self.metrics_mapper = {
            'ci_pending_builds': ('ci.builds', ['status:pending']),
            'ci_created_builds': ('ci.builds', ['status:created']),
            'ci_stale_builds': ('ci.builds', ['status:stale']),
            'ci_running_builds': ('ci.builds', ['status:running']),

            'git_pull_time_milliseconds': 'git.pull_time',
            'git_push_time_milliseconds': 'git.push_time',

            'process_age_seconds': 'git.process_age',
            'process_count': 'git.process_count',
            'process_memory_bytes': 'git.process_mem',

            'sidekiq_queue_size': 'sidekiq.queue_size',
            'sidekiq_queue_latency': 'sidekiq.queue_latency',
            'sidekiq_enqueued_jobs_count': ('sidekiq.jobs', ['status:enqueued']),
            'sidekiq_running_jobs_count': ('sidekiq.jobs', ['status:running']),
            'sidekiq_jobs_to_be_retried_count': ('sidekiq.jobs', ['status:to_retry']),
        }




    def check(self, instance):
        endpoint = instance.get('prometheus_endpoint')
        if endpoint is None:
            raise CheckException("Unable to find prometheus_endpoint in config file.")

        self.process(endpoint, instance=instance)
