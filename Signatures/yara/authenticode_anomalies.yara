import "pe"

rule research_pe_signed_outside_timestamp {
  meta:
    author = "David Cannings"
    description = "PE linker timestamp is outside the Authenticode validity period"

  strings:
    $mz = "MZ"

  condition:
    $mz at 0 and pe.number_of_signatures > 0 and not for all i in (0..pe.number_of_signatures - 1):
    (
      pe.signatures[i].valid_on(pe.timestamp)
    )
}