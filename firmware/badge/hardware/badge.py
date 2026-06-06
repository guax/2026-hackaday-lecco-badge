import asyncio as aio
from machine import I2C

from hardware import board
from hardware.datafile import Config
from hardware.display import Display
from hardware.keyboard import Keyboard
from net.lora import LoraRadio
from net.crypto import Crypto

badge_obj = None  # Singleton reference for use in the python shell for debugging

class Badge:
    """Badge object that manages all the badge's hardware and configuration.
    This is a singleton accessed by all the apps.
    From the REPL, you can `from hardware.badge import badge_obj` to get this.
    """
    def __init__(self):
        global badge_obj
        if badge_obj is not None:
            return
        badge_obj = self

        # Load badge config settings
        self.config = Config()
        # Initialize all the default values
        self._setup_defaults()

        print("Initializing badge hardware...")
        # Reserve controller 0 for the SAO header so it never collides with the keyboard bus.
        self.sao_i2c = I2C(0, scl=board.SAO_SCL, sda=board.SAO_SDA, freq=400000)

        # Helper functions to safely decode and parse config values
        def get_int(key):
            val = self.config.get(key)
            if val is None:
                raise ValueError("Config " + key + " is empty!")
            if isinstance(val, bytes):
                val = val.decode()
            try:
                return int(val)
            except ValueError:
                raise ValueError("Config " + key + " is not a valid int!")

        def get_float(key):
            val = self.config.get(key)
            if val is None:
                raise ValueError("Config " + key + " is empty!")
            if isinstance(val, bytes):
                val = val.decode()
            try:
                return float(val)
            except ValueError:
                raise ValueError("Config " + key + " is not a valid float!")

        board.DEBUG_LED.off()  # Default LED off

        # Setup radio
        tx_power = get_int("radio_tx_power")
        frequency = get_float("radio_frequency")
        bandwidth = get_float("radio_bandwidth")
        spreading_factor = get_int("radio_spreading_factor")
        coding_rate = get_int("radio_coding_rate")
        self.send_cooldown_ms = get_int("send_cooldown_ms")

        print (
            "Initializing LoRa radio tx power {}, frequency {}, bandwidth {}, SF{}, CR{}."
            .format(tx_power, frequency, bandwidth, spreading_factor, coding_rate)
        )
        self.lora: LoraRadio = LoraRadio(
            board.DEBUG_LED,
            tx_power=tx_power,
            frequency=frequency,
            bandwidth=bandwidth,
            spreading_factor=spreading_factor,
            coding_rate=coding_rate,
        )

        # Setup Display and Input
        self.display: Display = Display()
        self.display.backlight.duty(500)
        self.keyboard: Keyboard = Keyboard()

        self.crypto = Crypto()

        # Create task to run to check hardware, and update singleton reference
        self.task = aio.create_task(self.run())

    def _setup_defaults(self):
        self._setup_default_config_value("alias", "")
        self._setup_default_config_value("nametag", "Your Name Here!")
        self._setup_default_config_value("nametag_show_image", b'false')
        self._setup_default_config_value("nametag_image", b'images/headshots/wrencher.png')
        self._setup_default_config_value("radio_tx_power", b'9')
        self._setup_default_config_value("radio_frequency", b'869.525')
        self._setup_default_config_value("radio_bandwidth", b'250.0')
        self._setup_default_config_value("radio_spreading_factor", b'7')
        self._setup_default_config_value("radio_coding_rate", b'5')
        self._setup_default_config_value("chat_ttl", b'3')
        self._setup_default_config_value("send_cooldown_ms", b'1')

    def _setup_default_config_value(self, key, default_value):
        if key not in self.config.db.keys():
            print ("Key {} not found, initialized with {}.".format(key, default_value))
            self.config.set(key, default_value)

    async def run(self):
        print("Running badge task...")
        while True:
            await self.keyboard.read_hw()
            await aio.sleep_ms(1)

    def check_background_current_app(self):
        return False
