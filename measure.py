import subprocess
import re
import logging


def _adb_shell(args) -> str:
    return subprocess.check_output(['adb', 'shell'] + args, encoding='utf-8')


class TrafficMeasure:
    def __init__(self, uid: int):
        self._pattern = re.compile(
            r'''^
            \d+\            # idx
            \w+\            # iface
            0x[0-9a-f]+\    # acct_tag_hex
            ''' +
            str(uid) +      # uid_tag_int
            r'''\ 
            \d+\            # cnt_set
            (\d+)\          # rx_bytes
            \d+\            # rx_packets
            (\d+)           # tx_bytes
            ''', re.VERBOSE)

        self._uid = uid
        self._start_traffic = -1
        self._stop_traffic = -1

    def _measure(self) -> int:
        output = _adb_shell(['cat', '/proc/net/xt_qtaguid/stats'])
        traffic = 0

        # it is possible that no line matches
        for line in output.splitlines():
            match = self._pattern.match(line)
            if match:
                logging.debug(f'Traffic match: {line}')
                traffic += int(match.group(1))
                traffic += int(match.group(2))

        return traffic

    def start(self):
        self._start_traffic = self._measure()
        self._stop_traffic = -1
        logging.info(f'uid {self._uid} start traffic: {self._start_traffic}')

    def stop(self):
        if self._start_traffic < 0 or self._stop_traffic >= 0:
            raise Exception('Did you run start() before?')
        self._stop_traffic = self._measure()
        logging.info(f'uid {self._uid} stop traffic: {self._start_traffic}')

    def collect(self):
        if self._start_traffic < 0 or self._stop_traffic < 0:
            raise Exception('Did you run start() and stop() before?')
        return self._stop_traffic - self._start_traffic


class AndroidMeasure:
    def __init__(self, package: str):
        uid = self._get_uid(package)
        if not uid:
            raise ValueError(f'Package {package} not found.')
        logging.info(f"Package '{package}' uid = {uid}.")

        self.metric_names = ['network']
        self.metrics = [TrafficMeasure(uid)]

    def _get_uid(self, package: str) -> int:
        pattern = re.compile(r'\s*userId=(\d+)')
        output = _adb_shell(['dumpsys', 'package', package])
        for line in output.splitlines():
            match = pattern.fullmatch(line)
            if match:
                return int(match.group(1))
        return 0

    def start(self):
        for m in self.metrics:
            m.start()

    def stop(self):
        for m in self.metrics:
            m.stop()

    def collect(self):
        data = {}
        for n, m in zip(self.metric_names, self.metrics):
            data[n] = m.collect()
        return data
