#  type: ignore

from typing import ClassVar as _ClassVar
from typing import Optional as _Optional
from typing import Union as _Union

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper

DESCRIPTOR: _descriptor.FileDescriptor

# Generated with protoc --proto_path=src/launchpad/artifacts/android/resources/proto --python_out=src/launchpad/artifacts/android/resources/proto src/launchpad/artifacts/android/resources/proto/Configuration.proto src/launchpad/artifacts/android/resources/proto/Resources.proto --pyi_out=src/launchpad/artifacts/android/resources/proto
class Configuration(_message.Message):
    __slots__ = (
        "mcc",
        "mnc",
        "locale",
        "layout_direction",
        "screen_width",
        "screen_height",
        "screen_width_dp",
        "screen_height_dp",
        "smallest_screen_width_dp",
        "screen_layout_size",
        "screen_layout_long",
        "screen_round",
        "wide_color_gamut",
        "hdr",
        "orientation",
        "ui_mode_type",
        "ui_mode_night",
        "density",
        "touchscreen",
        "keys_hidden",
        "keyboard",
        "nav_hidden",
        "navigation",
        "sdk_version",
        "grammatical_gender",
        "product",
    )

    class LayoutDirection(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        LAYOUT_DIRECTION_UNSET: _ClassVar[Configuration.LayoutDirection]
        LAYOUT_DIRECTION_LTR: _ClassVar[Configuration.LayoutDirection]
        LAYOUT_DIRECTION_RTL: _ClassVar[Configuration.LayoutDirection]

    LAYOUT_DIRECTION_UNSET: Configuration.LayoutDirection
    LAYOUT_DIRECTION_LTR: Configuration.LayoutDirection
    LAYOUT_DIRECTION_RTL: Configuration.LayoutDirection

    class ScreenLayoutSize(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SCREEN_LAYOUT_SIZE_UNSET: _ClassVar[Configuration.ScreenLayoutSize]
        SCREEN_LAYOUT_SIZE_SMALL: _ClassVar[Configuration.ScreenLayoutSize]
        SCREEN_LAYOUT_SIZE_NORMAL: _ClassVar[Configuration.ScreenLayoutSize]
        SCREEN_LAYOUT_SIZE_LARGE: _ClassVar[Configuration.ScreenLayoutSize]
        SCREEN_LAYOUT_SIZE_XLARGE: _ClassVar[Configuration.ScreenLayoutSize]

    SCREEN_LAYOUT_SIZE_UNSET: Configuration.ScreenLayoutSize
    SCREEN_LAYOUT_SIZE_SMALL: Configuration.ScreenLayoutSize
    SCREEN_LAYOUT_SIZE_NORMAL: Configuration.ScreenLayoutSize
    SCREEN_LAYOUT_SIZE_LARGE: Configuration.ScreenLayoutSize
    SCREEN_LAYOUT_SIZE_XLARGE: Configuration.ScreenLayoutSize

    class ScreenLayoutLong(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SCREEN_LAYOUT_LONG_UNSET: _ClassVar[Configuration.ScreenLayoutLong]
        SCREEN_LAYOUT_LONG_LONG: _ClassVar[Configuration.ScreenLayoutLong]
        SCREEN_LAYOUT_LONG_NOTLONG: _ClassVar[Configuration.ScreenLayoutLong]

    SCREEN_LAYOUT_LONG_UNSET: Configuration.ScreenLayoutLong
    SCREEN_LAYOUT_LONG_LONG: Configuration.ScreenLayoutLong
    SCREEN_LAYOUT_LONG_NOTLONG: Configuration.ScreenLayoutLong

    class ScreenRound(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SCREEN_ROUND_UNSET: _ClassVar[Configuration.ScreenRound]
        SCREEN_ROUND_ROUND: _ClassVar[Configuration.ScreenRound]
        SCREEN_ROUND_NOTROUND: _ClassVar[Configuration.ScreenRound]

    SCREEN_ROUND_UNSET: Configuration.ScreenRound
    SCREEN_ROUND_ROUND: Configuration.ScreenRound
    SCREEN_ROUND_NOTROUND: Configuration.ScreenRound

    class WideColorGamut(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        WIDE_COLOR_GAMUT_UNSET: _ClassVar[Configuration.WideColorGamut]
        WIDE_COLOR_GAMUT_WIDECG: _ClassVar[Configuration.WideColorGamut]
        WIDE_COLOR_GAMUT_NOWIDECG: _ClassVar[Configuration.WideColorGamut]

    WIDE_COLOR_GAMUT_UNSET: Configuration.WideColorGamut
    WIDE_COLOR_GAMUT_WIDECG: Configuration.WideColorGamut
    WIDE_COLOR_GAMUT_NOWIDECG: Configuration.WideColorGamut

    class Hdr(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        HDR_UNSET: _ClassVar[Configuration.Hdr]
        HDR_HIGHDR: _ClassVar[Configuration.Hdr]
        HDR_LOWDR: _ClassVar[Configuration.Hdr]

    HDR_UNSET: Configuration.Hdr
    HDR_HIGHDR: Configuration.Hdr
    HDR_LOWDR: Configuration.Hdr

    class Orientation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ORIENTATION_UNSET: _ClassVar[Configuration.Orientation]
        ORIENTATION_PORT: _ClassVar[Configuration.Orientation]
        ORIENTATION_LAND: _ClassVar[Configuration.Orientation]
        ORIENTATION_SQUARE: _ClassVar[Configuration.Orientation]

    ORIENTATION_UNSET: Configuration.Orientation
    ORIENTATION_PORT: Configuration.Orientation
    ORIENTATION_LAND: Configuration.Orientation
    ORIENTATION_SQUARE: Configuration.Orientation

    class UiModeType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UI_MODE_TYPE_UNSET: _ClassVar[Configuration.UiModeType]
        UI_MODE_TYPE_NORMAL: _ClassVar[Configuration.UiModeType]
        UI_MODE_TYPE_DESK: _ClassVar[Configuration.UiModeType]
        UI_MODE_TYPE_CAR: _ClassVar[Configuration.UiModeType]
        UI_MODE_TYPE_TELEVISION: _ClassVar[Configuration.UiModeType]
        UI_MODE_TYPE_APPLIANCE: _ClassVar[Configuration.UiModeType]
        UI_MODE_TYPE_WATCH: _ClassVar[Configuration.UiModeType]
        UI_MODE_TYPE_VRHEADSET: _ClassVar[Configuration.UiModeType]

    UI_MODE_TYPE_UNSET: Configuration.UiModeType
    UI_MODE_TYPE_NORMAL: Configuration.UiModeType
    UI_MODE_TYPE_DESK: Configuration.UiModeType
    UI_MODE_TYPE_CAR: Configuration.UiModeType
    UI_MODE_TYPE_TELEVISION: Configuration.UiModeType
    UI_MODE_TYPE_APPLIANCE: Configuration.UiModeType
    UI_MODE_TYPE_WATCH: Configuration.UiModeType
    UI_MODE_TYPE_VRHEADSET: Configuration.UiModeType

    class UiModeNight(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UI_MODE_NIGHT_UNSET: _ClassVar[Configuration.UiModeNight]
        UI_MODE_NIGHT_NIGHT: _ClassVar[Configuration.UiModeNight]
        UI_MODE_NIGHT_NOTNIGHT: _ClassVar[Configuration.UiModeNight]

    UI_MODE_NIGHT_UNSET: Configuration.UiModeNight
    UI_MODE_NIGHT_NIGHT: Configuration.UiModeNight
    UI_MODE_NIGHT_NOTNIGHT: Configuration.UiModeNight

    class Touchscreen(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        TOUCHSCREEN_UNSET: _ClassVar[Configuration.Touchscreen]
        TOUCHSCREEN_NOTOUCH: _ClassVar[Configuration.Touchscreen]
        TOUCHSCREEN_STYLUS: _ClassVar[Configuration.Touchscreen]
        TOUCHSCREEN_FINGER: _ClassVar[Configuration.Touchscreen]

    TOUCHSCREEN_UNSET: Configuration.Touchscreen
    TOUCHSCREEN_NOTOUCH: Configuration.Touchscreen
    TOUCHSCREEN_STYLUS: Configuration.Touchscreen
    TOUCHSCREEN_FINGER: Configuration.Touchscreen

    class KeysHidden(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        KEYS_HIDDEN_UNSET: _ClassVar[Configuration.KeysHidden]
        KEYS_HIDDEN_KEYSEXPOSED: _ClassVar[Configuration.KeysHidden]
        KEYS_HIDDEN_KEYSHIDDEN: _ClassVar[Configuration.KeysHidden]
        KEYS_HIDDEN_KEYSSOFT: _ClassVar[Configuration.KeysHidden]

    KEYS_HIDDEN_UNSET: Configuration.KeysHidden
    KEYS_HIDDEN_KEYSEXPOSED: Configuration.KeysHidden
    KEYS_HIDDEN_KEYSHIDDEN: Configuration.KeysHidden
    KEYS_HIDDEN_KEYSSOFT: Configuration.KeysHidden

    class Keyboard(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        KEYBOARD_UNSET: _ClassVar[Configuration.Keyboard]
        KEYBOARD_NOKEYS: _ClassVar[Configuration.Keyboard]
        KEYBOARD_QWERTY: _ClassVar[Configuration.Keyboard]
        KEYBOARD_TWELVEKEY: _ClassVar[Configuration.Keyboard]

    KEYBOARD_UNSET: Configuration.Keyboard
    KEYBOARD_NOKEYS: Configuration.Keyboard
    KEYBOARD_QWERTY: Configuration.Keyboard
    KEYBOARD_TWELVEKEY: Configuration.Keyboard

    class NavHidden(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NAV_HIDDEN_UNSET: _ClassVar[Configuration.NavHidden]
        NAV_HIDDEN_NAVEXPOSED: _ClassVar[Configuration.NavHidden]
        NAV_HIDDEN_NAVHIDDEN: _ClassVar[Configuration.NavHidden]

    NAV_HIDDEN_UNSET: Configuration.NavHidden
    NAV_HIDDEN_NAVEXPOSED: Configuration.NavHidden
    NAV_HIDDEN_NAVHIDDEN: Configuration.NavHidden

    class Navigation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NAVIGATION_UNSET: _ClassVar[Configuration.Navigation]
        NAVIGATION_NONAV: _ClassVar[Configuration.Navigation]
        NAVIGATION_DPAD: _ClassVar[Configuration.Navigation]
        NAVIGATION_TRACKBALL: _ClassVar[Configuration.Navigation]
        NAVIGATION_WHEEL: _ClassVar[Configuration.Navigation]

    NAVIGATION_UNSET: Configuration.Navigation
    NAVIGATION_NONAV: Configuration.Navigation
    NAVIGATION_DPAD: Configuration.Navigation
    NAVIGATION_TRACKBALL: Configuration.Navigation
    NAVIGATION_WHEEL: Configuration.Navigation

    class GrammaticalGender(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        GRAM_GENDER_USET: _ClassVar[Configuration.GrammaticalGender]
        GRAM_GENDER_NEUTER: _ClassVar[Configuration.GrammaticalGender]
        GRAM_GENDER_FEMININE: _ClassVar[Configuration.GrammaticalGender]
        GRAM_GENDER_MASCULINE: _ClassVar[Configuration.GrammaticalGender]

    GRAM_GENDER_USET: Configuration.GrammaticalGender
    GRAM_GENDER_NEUTER: Configuration.GrammaticalGender
    GRAM_GENDER_FEMININE: Configuration.GrammaticalGender
    GRAM_GENDER_MASCULINE: Configuration.GrammaticalGender
    MCC_FIELD_NUMBER: _ClassVar[int]
    MNC_FIELD_NUMBER: _ClassVar[int]
    LOCALE_FIELD_NUMBER: _ClassVar[int]
    LAYOUT_DIRECTION_FIELD_NUMBER: _ClassVar[int]
    SCREEN_WIDTH_FIELD_NUMBER: _ClassVar[int]
    SCREEN_HEIGHT_FIELD_NUMBER: _ClassVar[int]
    SCREEN_WIDTH_DP_FIELD_NUMBER: _ClassVar[int]
    SCREEN_HEIGHT_DP_FIELD_NUMBER: _ClassVar[int]
    SMALLEST_SCREEN_WIDTH_DP_FIELD_NUMBER: _ClassVar[int]
    SCREEN_LAYOUT_SIZE_FIELD_NUMBER: _ClassVar[int]
    SCREEN_LAYOUT_LONG_FIELD_NUMBER: _ClassVar[int]
    SCREEN_ROUND_FIELD_NUMBER: _ClassVar[int]
    WIDE_COLOR_GAMUT_FIELD_NUMBER: _ClassVar[int]
    HDR_FIELD_NUMBER: _ClassVar[int]
    ORIENTATION_FIELD_NUMBER: _ClassVar[int]
    UI_MODE_TYPE_FIELD_NUMBER: _ClassVar[int]
    UI_MODE_NIGHT_FIELD_NUMBER: _ClassVar[int]
    DENSITY_FIELD_NUMBER: _ClassVar[int]
    TOUCHSCREEN_FIELD_NUMBER: _ClassVar[int]
    KEYS_HIDDEN_FIELD_NUMBER: _ClassVar[int]
    KEYBOARD_FIELD_NUMBER: _ClassVar[int]
    NAV_HIDDEN_FIELD_NUMBER: _ClassVar[int]
    NAVIGATION_FIELD_NUMBER: _ClassVar[int]
    SDK_VERSION_FIELD_NUMBER: _ClassVar[int]
    GRAMMATICAL_GENDER_FIELD_NUMBER: _ClassVar[int]
    PRODUCT_FIELD_NUMBER: _ClassVar[int]
    mcc: int
    mnc: int
    locale: str
    layout_direction: Configuration.LayoutDirection
    screen_width: int
    screen_height: int
    screen_width_dp: int
    screen_height_dp: int
    smallest_screen_width_dp: int
    screen_layout_size: Configuration.ScreenLayoutSize
    screen_layout_long: Configuration.ScreenLayoutLong
    screen_round: Configuration.ScreenRound
    wide_color_gamut: Configuration.WideColorGamut
    hdr: Configuration.Hdr
    orientation: Configuration.Orientation
    ui_mode_type: Configuration.UiModeType
    ui_mode_night: Configuration.UiModeNight
    density: int
    touchscreen: Configuration.Touchscreen
    keys_hidden: Configuration.KeysHidden
    keyboard: Configuration.Keyboard
    nav_hidden: Configuration.NavHidden
    navigation: Configuration.Navigation
    sdk_version: int
    grammatical_gender: Configuration.GrammaticalGender
    product: str
    def __init__(
        self,
        mcc: _Optional[int] = ...,
        mnc: _Optional[int] = ...,
        locale: _Optional[str] = ...,
        layout_direction: _Optional[_Union[Configuration.LayoutDirection, str]] = ...,
        screen_width: _Optional[int] = ...,
        screen_height: _Optional[int] = ...,
        screen_width_dp: _Optional[int] = ...,
        screen_height_dp: _Optional[int] = ...,
        smallest_screen_width_dp: _Optional[int] = ...,
        screen_layout_size: _Optional[_Union[Configuration.ScreenLayoutSize, str]] = ...,
        screen_layout_long: _Optional[_Union[Configuration.ScreenLayoutLong, str]] = ...,
        screen_round: _Optional[_Union[Configuration.ScreenRound, str]] = ...,
        wide_color_gamut: _Optional[_Union[Configuration.WideColorGamut, str]] = ...,
        hdr: _Optional[_Union[Configuration.Hdr, str]] = ...,
        orientation: _Optional[_Union[Configuration.Orientation, str]] = ...,
        ui_mode_type: _Optional[_Union[Configuration.UiModeType, str]] = ...,
        ui_mode_night: _Optional[_Union[Configuration.UiModeNight, str]] = ...,
        density: _Optional[int] = ...,
        touchscreen: _Optional[_Union[Configuration.Touchscreen, str]] = ...,
        keys_hidden: _Optional[_Union[Configuration.KeysHidden, str]] = ...,
        keyboard: _Optional[_Union[Configuration.Keyboard, str]] = ...,
        nav_hidden: _Optional[_Union[Configuration.NavHidden, str]] = ...,
        navigation: _Optional[_Union[Configuration.Navigation, str]] = ...,
        sdk_version: _Optional[int] = ...,
        grammatical_gender: _Optional[_Union[Configuration.GrammaticalGender, str]] = ...,
        product: _Optional[str] = ...,
    ) -> None: ...
