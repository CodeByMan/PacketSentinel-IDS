import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts import AlertSystem, alert_lock, alert_store


def test_alert_retention_is_bounded_under_concurrency(tmp_path):
    with alert_lock:
        alert_store.clear()
    system = AlertSystem(log_file=str(tmp_path / "alerts.log"), max_in_memory=25)

    def add_batch(worker):
        for index in range(20):
            system.trigger(f"192.0.2.{worker}", "Port Scan", details=f"event {index}")

    threads = [threading.Thread(target=add_batch, args=(worker,)) for worker in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    with alert_lock:
        assert len(alert_store) == 25
        assert all(alert["mitre"].startswith("T1046") for alert in alert_store)
