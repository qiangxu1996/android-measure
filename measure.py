import logging
import subprocess
import re
import threading
import time

logger = logging.getLogger(__name__)


def _adb_shell(args) -> str:
    return subprocess.check_output(['adb', 'shell'] + args, encoding='utf-8')


def _get_uid(package: str) -> int:
    pattern = re.compile(r'\s*userId=(\d+)')
    output = _adb_shell(['dumpsys', 'package', package])
    for line in output.splitlines():
        match = pattern.fullmatch(line)
        if match:
            return int(match.group(1))
    raise ValueError(f'Package {package} not found.')


class TwoPointMeasure:
    def __init__(self):
        self._start_data = None
        self._stop_data = None

    # TODO measure can have args or kwargs
    def measure(self):
        """
        :return: must not be None and must can do subtraction
        """
        raise NotImplementedError('Please override it.')

    def start(self):
        self._start_data = self.measure()
        self._stop_data = None
        logger.info(f'Start measure: {self._start_data}')

    def stop(self):
        if self._start_data is None or self._stop_data is not None:
            raise Exception('Did you run start() before?')
        self._stop_data = self.measure()
        logger.info(f'Stop measure: {self._stop_data}')

    def collect(self):
        if self._start_data is None or self._stop_data is None:
            raise Exception('Did you run start() and stop() before?')
        return self._stop_data - self._start_data


class TrafficMeasure(TwoPointMeasure):
    def __init__(self, uid: int):
        super().__init__()
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

    def measure(self) -> int:
        output = _adb_shell(['cat', '/proc/net/xt_qtaguid/stats'])
        traffic = 0

        # it is possible that no line matches
        for line in output.splitlines():
            match = self._pattern.match(line)
            if match:
                logger.debug(f'Traffic match: {line}')
                traffic += int(match.group(1))
                traffic += int(match.group(2))

        return traffic


class Periodic:
    def __init__(self, interval: int):
        self._interval = interval
        self._thread = None
        self._stop = threading.Event()

    def callback(self):
        raise NotImplementedError('Please override it.')

    def _run(self):
        logger.info(f'Thread {threading.current_thread().name} started.')
        while not self._stop.is_set():
            self.callback()
            # TODO check if callback time is significant
            time.sleep(self._interval)
        logger.info(f'Thread {threading.current_thread().name} exited.')

    def start(self):
        if self._thread:
            Exception('Already started.')
        self._thread = threading.Thread(target=self._run)
        self._stop.clear()
        self._thread.start()

    def stop(self):
        if self._stop.is_set() or not self._thread:
            raise Exception('Did you run start() before?')
        self._stop.set()
        self._thread.join()
        self._thread = None


class CpuMeasure(Periodic):
    def __init__(self, uid: int):
        super().__init__(5)
        self._uid = uid
        self._data = []

    def callback(self):
        output = _adb_shell(['ps', '-u', str(self._uid), '-o', 'PCPU'])
        pcpu = output.splitlines()
        del pcpu[0]  # the title
        pcpu = sum([float(p) for p in pcpu])
        logger.debug(f'uid = {self._uid} %CPU = {pcpu}')
        self._data.append(pcpu)

    def collect(self):
        return self._data


class MemMeasure(Periodic):
    def __init__(self, package: str):
        super().__init__(5)
        self._package = package
        self._data = []
        self._pattern = re.compile(r'\s*TOTAL:\s*(\d+)\s+TOTAL SWAP PSS:\s*\d+')

    def callback(self):
        output = _adb_shell(['dumpsys', 'meminfo', self._package])
        for line in output.splitlines():
            match = self._pattern.fullmatch(line)
            if match:
                logger.debug(f"'{self._package}': {line}")
                self._data.append(int(match.group(1)))  # KB
                return
        raise Exception(f"No mem info found for '{self._package}'.")

    def collect(self):
        return self._data


class AndroidMeasure:
    def __init__(self, package: str):
        uid = _get_uid(package)
        logger.info(f"Package '{package}' uid = {uid}.")

        self._metric_names = ['network', 'cpu', 'memory']
        self._metrics = [
            TrafficMeasure(uid),
            CpuMeasure(uid),
            MemMeasure(package)
        ]

    def start(self):
        for m in self._metrics:
            m.start()

    def stop(self):
        for m in self._metrics:
            m.stop()

    def collect(self):
        data = {}
        for n, m in zip(self._metric_names, self._metrics):
            data[n] = m.collect()
        return data
