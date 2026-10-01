"""Independent reproduction of manuscript sections 6.2-6.6.

These modules were absent from the original artifact; a reviewer could not
run them. They are new, additive code that only imports from the existing
``cape_artifact.algorithms`` and ``cape_artifact.models`` modules and does
not modify anything else in the artifact. They require no network access,
paid API, or credentials.

The generators here implement the methodology described in the manuscript
(same layouts, event cases, seed ranges, and cost conventions) but are an
independent reconstruction, not the original authors' generator code, so
exact digit-for-digit agreement with the published tables is not expected.
"""
