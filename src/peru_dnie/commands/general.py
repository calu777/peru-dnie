# Standard Library
from enum import Enum
from typing import Final

# Third Party Library
from rich.prompt import Prompt

# First Party Library
from peru_dnie.apdu import APDUCommand
from peru_dnie.context import Context
from peru_dnie.i18n import t


class PinType(Enum):
    SIGNATURE = 0x81
    ENCRYPTION = 0x83


SELECT_PKI_APP_CMD: Final = APDUCommand(
    cla=0x00,
    ins=0xA4,
    p1=0x04,
    p2=0x00,
    lc=0x0E,
    data=bytes(
        [
            0xE8,
            0x28,
            0xBD,
            0x08,
            0x0F,
            0xD2,
            0x50,
            0x47,
            0x65,
            0x6E,
            0x65,
            0x72,
            0x69,
            0x63,
        ]
    ),
)


_PIN_MIN_LEN = 4
_PIN_MAX_LEN = 16


def verify_pin(ctx: Context, *, pin_type: PinType) -> bool:
    """Verify the PIN before a DNIe cryptographic operation"""
    pin = Prompt.ask(
        t["general"]["enter_pin"],
        password=True,
        console=ctx.cli.console,
    )

    if len(pin) < _PIN_MIN_LEN:
        raise ValueError(t["errors"]["pin_too_short"])
    if len(pin) > _PIN_MAX_LEN:
        raise ValueError(t["errors"]["pin_too_long"])

    encoded_pin = bytearray(pin.encode("ascii"))

    try:
        verify_command = APDUCommand(
            cla=0x00,
            ins=0x20,
            p1=0x00,
            p2=pin_type.value,
            lc=len(encoded_pin),
            data=bytes(encoded_pin),
        )

        r = ctx.transmit(verify_command)
    finally:
        # Zero the PIN bytes in memory as soon as possible
        for i in range(len(encoded_pin)):
            encoded_pin[i] = 0

    if not r.ok:
        raise RuntimeError(t["errors"]["failed_pin"].format(repr(r)))

    return True
