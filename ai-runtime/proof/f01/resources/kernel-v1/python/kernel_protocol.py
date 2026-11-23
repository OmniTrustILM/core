"""Closed one-shot high gate and fixed net-rise calibration on parent counters."""
from fractions import Fraction
import math
import re


class ProtocolError(AssertionError):
    pass


def require(value, reason):
    if not value:
        raise ProtocolError(reason)


class StartGate:
    def __init__(self, pod_start):
        self.pod_start = pod_start
        self.pid = self.start = self.ready = self.signal = self.finished = None
        self.reads = []
        self.ack = self.complete = False
        self.last = pod_start

    def signal_started(self, now):
        require(self.ready is not None and self.signal is None and self.ready < now and
                now <= self.pod_start + 10, 'GATE_ORDER')
        self.signal = now

    def signal_finished(self, now):
        require(self.signal is not None and self.finished is None and self.signal <= now and
                now <= self.pod_start + 12, 'GATE_ORDER')
        self.finished = now

    def feed(self, message, received):
        require(type(message) is str and message.isascii() and len(message) <= 256 and
                type(received) in (int, float) and math.isfinite(received) and
                self.last <= received, 'GATE_ORDER')
        self.last = received
        match = re.fullmatch(r'CG_READY pid=([1-9][0-9]{0,14}) start=([1-9][0-9]{0,14})', message)
        if match:
            require(self.ready is None and received <= self.pod_start + 10, 'GATE_ORDER')
            self.pid, self.start = map(int, match.groups())
            self.ready = received
            return
        require(self.finished is not None and received >= self.finished and
                received <= self.pod_start + 14, 'GATE_ORDER')
        match = re.fullmatch(r'CG_RAW attempt=([12]) rc=(0|[1-9][0-9]{0,2}) count=1 token=(GO|)', message)
        if match:
            attempt, code = map(int, match.groups()[:2]);token = match[3]
            require(not self.ack and attempt == len(self.reads) + 1 and code <= 255 and
                    (not self.reads or self.reads == [1]) and
                    ((code == 0 and token == 'GO') or
                     (code > 0 and token == '' and attempt == 1)), 'GATE_ORDER')
            self.reads.append(0 if code == 0 else 1)
            return
        match = re.fullmatch(r'CG_ACK pid=([1-9][0-9]{0,14}) start=([1-9][0-9]{0,14}) count=1', message)
        if match:
            require(not self.ack and self.reads in ([0], [1, 0]) and
                    tuple(map(int, match.groups())) == (self.pid, self.start), 'GATE_ORDER')
            self.ack = True
            return
        require(message == 'CG_LOAD_BEGIN' and self.ack and not self.complete, 'GATE_ORDER')
        self.complete = True


def complete_window(rows):
    return (len(rows) >= 3 and
            Fraction(rows[-1]['counterReadStart']) - Fraction(rows[0]['counterReadEnd']) >= 1)


def calibration_result(rows, phases, terminal, ops):
    """No fabricated snapshot/groups schema: reuse only pure scalar/event validators."""
    phases.complete()
    require(terminal['exitCode'] == 0 and len(phases.signal_starts) == 3, 'CALIBRATION_TERMINAL')
    names = ('READY', 'NO_EFFECT', 'EFFECT_HELD', 'RELEASED')
    require(set(phases.markers) == set(names) | {'HOLD_END'}, 'CALIBRATION_PHASES')
    require(type(rows) is list and 1 <= len(rows) <= 400, 'CALIBRATION_ROWS')
    windows = {};values = []
    for index, row in enumerate(rows):
        require(row['sample'] == index and row['status'] == 'verified' and
                row['counterReadStart'] <= row['counterReadEnd'], 'CALIBRATION_ROWS')
        current = row['counters'];scalar = ops['_accounting_scalar'](current)
        ops['_accounting_counter_events'](current, scalar, values[-1] if values else None)
        require(not current['pids.events']['max'] and
                not any(current['memory.events'][key] for key in ('max', 'oom', 'oom_kill')) and
                not current['memory.events'].get('oom_group_kill', 0), 'COUNTER_INTERFERENCE')
        if values:
            require(scalar['memory.peak'] >= values[-1]['memory.peak'], 'COUNTER_RESET')
        values.append(scalar)
    for index, name in enumerate(names):
        lower = phases.markers[name]['receivedMonotonic']
        upper = phases.signal_starts[index] if index < 3 else phases.markers['HOLD_END']['receivedMonotonic']
        require(lower < upper, 'CALIBRATION_PHASES')
        windows[name] = [row for row in rows if lower <= row['counterReadStart'] and
                         row['counterReadEnd'] <= upper]
        require(complete_window(windows[name]), 'INSUFFICIENT_WINDOW')
    baseline = [values[row['sample']]['memory.current']
                for phase in ('READY', 'NO_EFFECT') for row in windows[phase]]
    low, high = min(baseline), max(baseline)
    noise = high - low
    require(2 * noise < 4194304, 'MEMORY_BASELINE_NOISE')
    require(all(values[row['sample']]['memory.current'] >= high + 4194304
                for row in windows['EFFECT_HELD']), 'MEMORY_NO_RISE')
    require(all(values[row['sample']]['memory.current'] <= high + noise
                for row in windows['RELEASED']), 'MEMORY_NO_RETURN')
    return {'status': 'OBSERVED', 'claim': 'COINCIDENT_OWNED_POD_PARENT_CHARGE_AND_RETURN',
            'baselineMin': low, 'baselineMax': high, 'noise': noise, 'logicalPayloadBytes': 8388608,
            'minimumRiseBytes': 4194304,
            'windowCounts': {name: len(value) for name, value in windows.items()},
            'measurement': 'PER_READ_HIERARCHICAL_PARENT_NOT_ATOMIC_TASK_CENSUS',
            'fullF01Accepted': False}
