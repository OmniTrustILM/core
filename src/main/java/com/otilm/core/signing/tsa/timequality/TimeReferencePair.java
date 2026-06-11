package com.otilm.core.signing.tsa.timequality;

record TimeReferencePair(long wallTimeMillis, long monotonicNanos, double measuredDriftMs) {
}
