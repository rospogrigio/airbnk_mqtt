from __future__ import annotations
import logging

from datetime import datetime

_LOGGER = logging.getLogger(__name__)

LOG_PERSISTENCE_SECS = 300


class AirbnkLogger:
    def __init__(self, log_name):
        self.logger = logging.getLogger(log_name)
        self.log = []

    def append_to_log(self, log_level, msg):
        systemTime = datetime.now().timestamp()
        self.log.append({"time": systemTime, "level": log_level, "msg": msg})
        while self.log[0]["time"] < systemTime - LOG_PERSISTENCE_SECS:
            self.log = self.log[1:]

    def retrieve_log(self):
        output = []
        for record in self.log:
            t_stamp = datetime.fromtimestamp(record["time"])
            t_stamp_str = t_stamp.strftime("%Y-%m-%d %H:%M:%S ")
            output.append(t_stamp_str + record["level"] + ": " + record["msg"])
        return output

    def info(self, msg):
        self.append_to_log("INFO", msg)
        self.logger.info(msg)

    def debug(self, msg):
        self.append_to_log("DEBUG", msg)
        self.logger.debug(msg)

    def warning(self, msg):
        self.append_to_log("WARNING", msg)
        self.logger.warning(msg)

    def error(self, msg):
        self.append_to_log("ERROR", msg)
        self.logger.error(msg)
