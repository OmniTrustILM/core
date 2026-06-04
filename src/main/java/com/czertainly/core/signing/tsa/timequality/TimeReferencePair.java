package com.czertainly.core.signing.tsa.timequality;

record TimeReferencePair(long wallTimeMillis, long monotonicNanos, double measuredDriftMs) {
}
