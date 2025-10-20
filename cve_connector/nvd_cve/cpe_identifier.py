from dataclasses import dataclass


@dataclass
class CpeIdentifier:
    part: str
    vendor: str
    product: str
    version: str
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"

    def to_cpe23_string(self) -> str:
        return (
            f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{self.version}:"
            f"{self.update}:{self.edition}:{self.language}:{self.sw_edition}:"
            f"{self.target_sw}:{self.target_hw}:{self.other}"
        )

    @staticmethod
    def from_string(cpe_str: str) -> "CpeIdentifier":
        parts = cpe_str.split(":")

        if not parts or parts[0] != "cpe":
            raise ValueError(f"Invalid CPE string: {cpe_str}")

        if parts[1] == "2.3":
            # CPE 2.3 format
            parts += ["*"] * (13 - len(parts))
            return CpeIdentifier(
                part=parts[2],
                vendor=parts[3],
                product=parts[4],
                version=parts[5],
                update=parts[6] or "*",
                edition=parts[7] or "*",
                language=parts[8] or "*",
                sw_edition=parts[9] or "*",
                target_sw=parts[10] or "*",
                target_hw=parts[11] or "*",
                other=parts[12] or "*",
            )

        # Legacy CPE 2.2 format: "cpe:/part:vendor:product:version"
        if parts[1].startswith("/"):
            legacy_parts = parts[1][1:].split(":")
            legacy_parts += ["*"] * (4 - len(legacy_parts))
            return CpeIdentifier(
                part=legacy_parts[0], vendor=legacy_parts[1], product=legacy_parts[2], version=legacy_parts[3]
            )

        raise ValueError(f"Unrecognized CPE format: {cpe_str}")
