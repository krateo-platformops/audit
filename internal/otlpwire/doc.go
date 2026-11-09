// Package otlpwire holds only tests: they send audit records through the real
// otlploghttp exporter to a test collector, so the proof that a sanitised
// record survives the OTLP wire does not rest on a fake. It lives apart from
// the audit package so the exporter is a test dependency of this package
// alone.
package otlpwire
