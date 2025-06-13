from typing import Any, Dict, List

from ..buffer_wrapper import BufferWrapper
from .types import (
    ChunkHeader,
    ChunkType,
    Dimension,
    EntryFlags,
    Fraction,
    NodeType,
    ResourceTableEntry,
    ResourceTablePackage,
    ResourceTableType,
    ResourceTypeConfig,
    StringFlags,
    StringPool,
    TypedValue,
    TypedValueRawType,
    TypeFlags,
    XmlAttribute,
    XmlCData,
    XmlNode,
)


# Parser for Android binary files (axml, arsc)
# Definitions: https://android.googlesource.com/platform/frameworks/base/+/56a2301/include/androidfw/ResourceTypes.h
class AndroidBinaryParser:
    def __init__(self, buffer: bytes):
        self.buffer_wrapper = BufferWrapper(buffer)
        self.strings: List[str] = []
        self.resources: List[int] = []
        self.document: XmlNode | None = None
        self.parent: XmlNode | None = None
        self.stack: List[XmlNode] = []
        self.string_pool: StringPool | None = None
        self.packages: List[ResourceTablePackage] = []

    def read_chunk_header(self) -> ChunkHeader:
        """Read a chunk header from the buffer."""
        start_offset = self.buffer_wrapper.cursor
        chunk_type = self.buffer_wrapper.read_u16()
        header_size = self.buffer_wrapper.read_u16()
        chunk_size = self.buffer_wrapper.read_u32()
        return ChunkHeader(
            start_offset=start_offset,
            chunk_type=ChunkType(chunk_type),
            header_size=header_size,
            chunk_size=chunk_size,
        )

    def read_string_pool(self, header: ChunkHeader) -> StringPool:
        """Read a string pool chunk from the buffer."""
        string_count = self.buffer_wrapper.read_u32()
        style_count = self.buffer_wrapper.read_u32()
        flags = self.buffer_wrapper.read_u32()
        strings_start = self.buffer_wrapper.read_u32()
        styles_start = self.buffer_wrapper.read_u32()

        if header.chunk_type != ChunkType.STRING_POOL:
            raise ValueError("Invalid string pool header")

        offsets = [self.buffer_wrapper.read_u32() for _ in range(string_count)]
        encoding = "utf-8" if (flags & StringFlags.UTF8) == StringFlags.UTF8 else "utf-16le"
        adjusted_strings_start = header.start_offset + strings_start

        strings: List[str] = []
        for i in range(string_count):
            self.buffer_wrapper.cursor = adjusted_strings_start + offsets[i]
            if encoding == "utf-8":
                string_length = self.buffer_wrapper.read_length8()
                byte_length = self.buffer_wrapper.read_length8()
                value = self.buffer_wrapper.read_string_with_length(byte_length)
                if self.buffer_wrapper.read_u8() != 0:
                    raise ValueError("String must end with trailing zero")
            else:
                string_length = self.buffer_wrapper.read_length16()
                byte_length = string_length * 2
                value = self.buffer_wrapper.read_string_with_length(byte_length)
                if self.buffer_wrapper.read_u16() != 0:
                    raise ValueError("String must end with trailing zero")
            strings.append(value)
            self.strings.append(value)

        self.buffer_wrapper.cursor = header.start_offset + header.chunk_size
        return StringPool(
            strings=strings,
            flags=flags,
            string_count=string_count,
            strings_start=strings_start,
            style_count=style_count,
            styles_start=styles_start,
        )

    def read_resource_map(self, header: ChunkHeader) -> None:
        """Read a resource map chunk from the buffer."""
        count = (header.chunk_size - header.header_size) // 4
        for _ in range(count):
            self.resources.append(self.buffer_wrapper.read_u32())

    def read_xml_namespace_start(self) -> None:
        """Read an XML namespace start chunk from the buffer."""
        self.buffer_wrapper.read_u32()  # line
        self.buffer_wrapper.read_u32()  # commentRef
        self.buffer_wrapper.read_s32()  # prefixRef
        self.buffer_wrapper.read_s32()  # uriRef

    def read_xml_namespace_end(self) -> None:
        """Read an XML namespace end chunk from the buffer."""
        self.buffer_wrapper.read_u32()  # line
        self.buffer_wrapper.read_u32()  # commentRef
        self.buffer_wrapper.read_s32()  # prefixRef
        self.buffer_wrapper.read_s32()  # uriRef

    def read_xml_element_start(self) -> XmlNode:
        """Read an XML element start chunk from the buffer."""
        self.buffer_wrapper.read_u32()  # line
        self.buffer_wrapper.read_u32()  # commentRef
        ns_ref = self.buffer_wrapper.read_s32()
        name_ref = self.buffer_wrapper.read_s32()

        namespace_uri = self.strings[ns_ref] if ns_ref > 0 else None
        node_name = self.strings[name_ref]

        self.buffer_wrapper.read_u16()  # attrStart
        self.buffer_wrapper.read_u16()  # attrSize
        attr_count = self.buffer_wrapper.read_u16()
        self.buffer_wrapper.read_u16()  # idIndex
        self.buffer_wrapper.read_u16()  # classIndex
        self.buffer_wrapper.read_u16()  # styleIndex

        attributes = [self.read_xml_attribute() for _ in range(attr_count)]
        node = XmlNode(
            node_type=NodeType.ELEMENT_NODE,
            attributes=attributes,
            child_nodes=[],
            node_name=node_name,
            namespace_uri=namespace_uri,
        )

        if self.document:
            if self.parent:
                self.parent.child_nodes.append(node)
            self.parent = node
        else:
            self.parent = node
            self.document = node

        self.stack.append(node)
        return node

    def read_xml_attribute(self) -> XmlAttribute:
        """Read an XML attribute from the buffer."""
        ns_ref = self.buffer_wrapper.read_s32()
        name_ref = self.buffer_wrapper.read_s32()
        value_ref = self.buffer_wrapper.read_s32()

        namespace_uri = self.strings[ns_ref] if ns_ref > 0 else None
        node_name = self.strings[name_ref]

        # If the name is empty, try to get the resource string from the resource map
        if not node_name and name_ref < len(self.resources):
            resource_id = self.resources[name_ref]
            if resource_id:
                node_name = self.get_resource_string(resource_id)

        value = self.strings[value_ref] if value_ref > 0 else None
        typed_value = self.read_typed_value()

        return XmlAttribute(
            name=node_name,
            node_type=NodeType.ATTRIBUTE_NODE,
            namespace_uri=namespace_uri,
            node_name=node_name,
            typed_value=typed_value,
            value=value,
        )

    def read_xml_element_end(self) -> None:
        """Read an XML element end chunk from the buffer."""
        self.buffer_wrapper.read_u32()  # line
        self.buffer_wrapper.read_u32()  # commentRef
        self.buffer_wrapper.read_s32()  # nsRef
        self.buffer_wrapper.read_s32()  # nameRef
        self.stack.pop()
        self.parent = self.stack[-1] if self.stack else None

    def read_xml_cdata(self) -> XmlCData:
        """Read an XML CDATA chunk from the buffer."""
        self.buffer_wrapper.read_u32()  # line
        self.buffer_wrapper.read_u32()  # commentRef
        data_ref = self.buffer_wrapper.read_s32()

        data = self.strings[data_ref] if data_ref > 0 else None
        typed_value = self.read_typed_value()

        cdata = XmlCData(
            attributes=[],
            child_nodes=[],
            node_type=NodeType.CDATA_SECTION_NODE,
            node_name="#cdata",
            data=data,
            typed_value=typed_value,
        )

        if self.parent:
            self.parent.child_nodes.append(cdata)

        return cdata

    def read_package_name(self) -> str:
        """Read a package name from the buffer."""
        offset = self.buffer_wrapper.cursor
        length = 0
        for i in range(offset, min(offset + 256, len(self.buffer_wrapper.buffer)), 2):
            if self.buffer_wrapper.buffer[i] == 0 and self.buffer_wrapper.buffer[i + 1] == 0:
                length = i - offset
                break

        value = self.buffer_wrapper.buffer[offset : offset + length].decode("utf-16le")
        self.buffer_wrapper.cursor = offset + 256
        return value

    def read_package(self, header: ChunkHeader) -> ResourceTablePackage:
        """Read a package chunk from the buffer."""
        package_end = header.start_offset + header.chunk_size

        id_val = self.buffer_wrapper.read_u32()
        name = self.read_package_name()

        type_strings_offset = self.buffer_wrapper.read_u32()
        self.buffer_wrapper.read_u32()  # lastPublicType
        key_strings_offset = self.buffer_wrapper.read_u32()
        self.buffer_wrapper.read_u32()  # lastPublicKey
        self.buffer_wrapper.read_u32()  # typeIdOffset

        # Read type strings pool
        self.buffer_wrapper.cursor = header.start_offset + type_strings_offset
        types_string_pool_header = self.read_chunk_header()
        types_string_pool = self.read_string_pool(types_string_pool_header)

        # Read key strings pool
        self.buffer_wrapper.cursor = header.start_offset + key_strings_offset
        keys_string_pool_header = self.read_chunk_header()
        keys_string_pool = self.read_string_pool(keys_string_pool_header)

        # Parse type chunks within the package
        types: List[ResourceTableType] = []
        self.buffer_wrapper.cursor = header.start_offset + header.header_size
        while self.buffer_wrapper.cursor < package_end:
            chunk_header = self.read_chunk_header()

            if chunk_header.chunk_type == ChunkType.TABLE_TYPE:
                types.append(self.read_type_chunk(chunk_header, types_string_pool, keys_string_pool))
            elif chunk_header.chunk_type in (ChunkType.TABLE_LIBRARY, ChunkType.TABLE_TYPE_SPEC, ChunkType.NULL):
                self.buffer_wrapper.cursor = chunk_header.start_offset + chunk_header.chunk_size
            else:
                self.buffer_wrapper.cursor = chunk_header.start_offset + chunk_header.chunk_size

        return ResourceTablePackage(
            id=id_val,
            name=name,
            types=types,
        )

    def read_type_chunk(
        self, header: ChunkHeader, type_strings_pool: StringPool, keys_string_pool: StringPool
    ) -> ResourceTableType:
        """Read a type chunk from the buffer."""
        id_val = self.buffer_wrapper.read_u8()
        flags = self.buffer_wrapper.read_u8()
        reserved = self.buffer_wrapper.read_u16()
        if reserved != 0:
            raise ValueError(f"Reserved field is not 0: {reserved}")

        entries_count = self.buffer_wrapper.read_u32()
        entries_start = self.buffer_wrapper.read_u32()

        name = type_strings_pool.strings[id_val - 1]
        config = self.read_type_config()

        is_sparse = (flags & TypeFlags.SPARSE) != 0
        entries: List[ResourceTableEntry] = []

        if is_sparse:
            start = self.buffer_wrapper.cursor
            for i in range(entries_count):
                self.buffer_wrapper.cursor = start + i * 4
                index = self.buffer_wrapper.read_u16() & 0xFFFF
                entry_offset = (self.buffer_wrapper.read_u16() & 0xFFFF) * 4
                entry = self.create_entry(
                    header.start_offset + entries_start + entry_offset,
                    index,
                    keys_string_pool,
                )
                entries.append(entry)
        else:
            start = self.buffer_wrapper.cursor
            for i in range(entries_count):
                self.buffer_wrapper.cursor = start + i * 4
                entry_offset = self.buffer_wrapper.read_u32()
                if entry_offset == 0xFFFFFFFF:
                    continue
                entry = self.create_entry(
                    header.start_offset + entries_start + entry_offset,
                    i,
                    keys_string_pool,
                )
                entries.append(entry)

        self.buffer_wrapper.cursor = header.start_offset + header.chunk_size

        return ResourceTableType(
            id=id_val,
            name=name,
            config=config,
            entries=entries,
        )

    def create_entry(self, offset: int, index: int, keys_string_pool: StringPool) -> ResourceTableEntry:
        """Create a resource table entry from the buffer."""
        self.buffer_wrapper.cursor = offset

        size = self.buffer_wrapper.read_u16()
        flags = self.buffer_wrapper.read_u16()
        key_index = self.buffer_wrapper.read_u32()
        key = keys_string_pool.strings[key_index]

        parent_entry = 0
        value: TypedValue | None = None
        values: Dict[int, TypedValue] = {}

        if (flags & EntryFlags.COMPLEX) != 0:
            parent_entry = self.buffer_wrapper.read_u32()
            count_or_value = self.buffer_wrapper.read_u32()

            for _ in range(count_or_value):
                entry_offset = self.buffer_wrapper.read_u32()
                v = self.read_typed_value()
                values[entry_offset] = v
        else:
            value = self.read_typed_value()

        return ResourceTableEntry(
            size=size,
            flags=flags,
            id=index,
            key=key,
            parent_entry=parent_entry,
            value=value,
            values=values,
        )

    def read_type_config(self) -> ResourceTypeConfig:
        """Read a type configuration from the buffer."""
        start = self.buffer_wrapper.cursor

        size = self.buffer_wrapper.read_u32()
        self.buffer_wrapper.read_u16()  # mcc
        self.buffer_wrapper.read_u16()  # mnc
        language = self.buffer_wrapper.read_string_with_length(2)
        region = self.buffer_wrapper.read_string_with_length(2)

        self.buffer_wrapper.cursor = start + size

        return ResourceTypeConfig(
            size=size,
            language=language,
            region=region,
        )

    def read_typed_value(self) -> TypedValue:
        """Read a typed value from the buffer."""
        start = self.buffer_wrapper.cursor

        size = self.buffer_wrapper.read_u16()
        reserved = self.buffer_wrapper.read_u8()
        if reserved != 0:
            raise ValueError(f"Reserved field is not 0: {reserved}")

        raw_type = self.buffer_wrapper.read_u8()
        if size == 0:
            size = 8

        value: Any
        if raw_type == TypedValueRawType.TYPE_INT_DEC or raw_type == TypedValueRawType.TYPE_INT_HEX:
            value = self.buffer_wrapper.read_s32()
        elif raw_type == TypedValueRawType.TYPE_STRING:
            ref = self.buffer_wrapper.read_u32()
            value = self.strings[ref] if ref >= 0 else ""
        elif raw_type == TypedValueRawType.TYPE_REFERENCE:
            id_val = self.buffer_wrapper.read_u32()
            value = f"resourceId:0x{id_val:x}"
        elif raw_type == TypedValueRawType.TYPE_INT_BOOLEAN:
            value = self.buffer_wrapper.read_s32() != 0
        elif raw_type == TypedValueRawType.TYPE_NULL:
            self.buffer_wrapper.read_u32()
            value = None
        elif raw_type == TypedValueRawType.TYPE_INT_COLOR_RGB8 or raw_type == TypedValueRawType.TYPE_INT_COLOR_RGB4:
            value = f"#{self.buffer_wrapper.read_u32() & 0xFFFFFF:06x}"
        elif raw_type == TypedValueRawType.TYPE_INT_COLOR_ARGB8 or raw_type == TypedValueRawType.TYPE_INT_COLOR_ARGB4:
            value = f"#{self.buffer_wrapper.read_u32():08x}"
        elif raw_type == TypedValueRawType.TYPE_DIMENSION:
            value = self.read_dimension()
        elif raw_type == TypedValueRawType.TYPE_FRACTION:
            value = self.read_fraction()
        else:
            value = self.buffer_wrapper.read_u32()

        # Ensure we consume the whole value
        end = start + size
        if self.buffer_wrapper.cursor != end:
            self.buffer_wrapper.cursor = end

        return TypedValue(
            value=value,
            type=self.typed_value_name_from_id(raw_type),
            raw_type=raw_type,
        )

    def read_dimension(self) -> Dimension:
        """Read a dimension value from the buffer."""
        value = self.buffer_wrapper.read_u32()
        raw_unit = value & 0xFF
        dimension_value = value >> 8

        unit_map = {
            TypedValueRawType.COMPLEX_UNIT_MM: "mm",
            TypedValueRawType.COMPLEX_UNIT_PX: "px",
            TypedValueRawType.COMPLEX_UNIT_DIP: "dp",
            TypedValueRawType.COMPLEX_UNIT_SP: "sp",
            TypedValueRawType.COMPLEX_UNIT_PT: "pt",
            TypedValueRawType.COMPLEX_UNIT_IN: "in",
        }
        dimension_unit = unit_map.get(raw_unit, f"unknown ({raw_unit})")  # type: ignore[call-overload]

        return Dimension(
            value=dimension_value,
            unit=dimension_unit,
            raw_unit=raw_unit,
        )

    def read_fraction(self) -> Fraction:
        """Read a fraction value from the buffer."""
        value = self.buffer_wrapper.read_u32()
        type_val = value & 0xF
        fraction_value = self.convert_int_to_float(value >> 4)

        type_map = {
            TypedValueRawType.COMPLEX_UNIT_FRACTION: "%",
            TypedValueRawType.COMPLEX_UNIT_FRACTION_PARENT: "%p",
        }
        fraction_type = type_map.get(type_val, f"unknown ({type_val})")  # type: ignore[call-overload]

        return Fraction(
            value=fraction_value,
            type=fraction_type,
            raw_type=type_val,
        )

    def convert_int_to_float(self, int_val: int) -> float:
        """Convert an integer to a float using IEEE 754 representation."""
        import struct

        return struct.unpack("<f", struct.pack("<I", int_val))[0]  # type: ignore[no-any-return]

    def typed_value_name_from_id(self, id_val: int) -> str:
        """Get the name of a typed value from its ID."""
        type_map: dict[int, str] = {
            TypedValueRawType.TYPE_INT_DEC: "int_dec",
            TypedValueRawType.TYPE_INT_HEX: "int_hex",
            TypedValueRawType.TYPE_STRING: "string",
            TypedValueRawType.TYPE_REFERENCE: "reference",
            TypedValueRawType.TYPE_INT_BOOLEAN: "boolean",
            TypedValueRawType.TYPE_NULL: "null",
            TypedValueRawType.TYPE_INT_COLOR_RGB8: "rgb8",
            TypedValueRawType.TYPE_INT_COLOR_RGB4: "rgb4",
            TypedValueRawType.TYPE_INT_COLOR_ARGB8: "argb8",
            TypedValueRawType.TYPE_INT_COLOR_ARGB4: "argb4",
            TypedValueRawType.TYPE_DIMENSION: "dimension",
            TypedValueRawType.TYPE_FRACTION: "fraction",
        }
        return type_map.get(id_val, f"unknown (0x{id_val:x})")

    def parse_xml(self) -> XmlNode:
        """Parse an XML document from the buffer."""
        main_chunk_header = self.read_chunk_header()
        if main_chunk_header.chunk_type != ChunkType.XML:
            raise ValueError(f"Invalid main chunk header: {main_chunk_header.chunk_type}")

        while self.buffer_wrapper.cursor < len(self.buffer_wrapper.buffer):
            start = self.buffer_wrapper.cursor
            header = self.read_chunk_header()

            if header.chunk_type == ChunkType.STRING_POOL:
                self.string_pool = self.read_string_pool(header)
            elif header.chunk_type == ChunkType.XML_RESOURCE_MAP:
                self.read_resource_map(header)
            elif header.chunk_type == ChunkType.XML_START_NAMESPACE:
                self.read_xml_namespace_start()
            elif header.chunk_type == ChunkType.XML_END_NAMESPACE:
                self.read_xml_namespace_end()
            elif header.chunk_type == ChunkType.XML_START_ELEMENT:
                self.read_xml_element_start()
            elif header.chunk_type == ChunkType.XML_END_ELEMENT:
                self.read_xml_element_end()
            elif header.chunk_type == ChunkType.XML_CDATA:
                self.read_xml_cdata()
            elif header.chunk_type == ChunkType.NULL:
                self.buffer_wrapper.cursor = header.start_offset + header.chunk_size
            else:
                self.buffer_wrapper.cursor = header.start_offset + header.chunk_size

            # Ensure we consume the whole chunk
            end = start + header.chunk_size
            if self.buffer_wrapper.cursor != end:
                self.buffer_wrapper.cursor = end

        if not self.document:
            raise ValueError("No XML document found")

        return self.document

    def parse_resource_table(self) -> None:
        """Parse a resource table from the buffer."""
        self.buffer_wrapper.cursor = 0

        main_chunk_header = self.read_chunk_header()
        if main_chunk_header.chunk_type != ChunkType.TABLE:
            raise ValueError(f"Invalid main chunk type: {main_chunk_header.chunk_type}")

        self.buffer_wrapper.read_u32()  # Packages

        if len(self.buffer_wrapper.buffer) <= 40:
            # Apps with no resources will be exactly 40 bytes
            return

        while self.buffer_wrapper.cursor < len(self.buffer_wrapper.buffer):
            start = self.buffer_wrapper.cursor
            header = self.read_chunk_header()

            if header.chunk_type == ChunkType.STRING_POOL:
                self.string_pool = self.read_string_pool(header)
            elif header.chunk_type == ChunkType.TABLE_PACKAGE:
                self.packages.append(self.read_package(header))
            elif header.chunk_type == ChunkType.NULL:
                self.buffer_wrapper.cursor = header.start_offset + header.chunk_size
            else:
                raise ValueError(f"Unsupported chunk type '0x{header.chunk_type:x}'")

            # Ensure we consume the whole chunk
            end = start + header.chunk_size
            if self.buffer_wrapper.cursor != end:
                self.buffer_wrapper.cursor = end

    # https://github.com/Ayrx/axmldecoder/blob/680ec1552199666b60b0b6a479dfc63d7f4b6f82/src/xml.rs#L221
    def get_resource_string(self, resource_id: int) -> str:
        """Get a resource string from its ID."""
        i = resource_id - 0x01010000
        if 0 <= i < len(self.RESOURCE_STRINGS):
            return self.RESOURCE_STRINGS[i]
        return "UNKNOWN"

    # Resource string table from Android framework
    RESOURCE_STRINGS = [
        "theme",
        "label",
        "icon",
        "name",
        "manageSpaceActivity",
        "allowClearUserData",
        "permission",
        "readPermission",
        "writePermission",
        "protectionLevel",
        "permissionGroup",
        "sharedUserId",
        "hasCode",
        "persistent",
        "enabled",
        "debuggable",
        "exported",
        "process",
        "taskAffinity",
        "multiprocess",
        "finishOnTaskLaunch",
        "clearTaskOnLaunch",
        "stateNotNeeded",
        "excludeFromRecents",
        "authorities",
        "syncable",
        "initOrder",
        "grantUriPermissions",
        "priority",
        "launchMode",
        "screenOrientation",
        "configChanges",
        "description",
        "targetPackage",
        "handleProfiling",
        "functionalTest",
        "value",
        "resource",
        "mimeType",
        "scheme",
        "host",
        "port",
        "path",
        "pathPrefix",
        "pathPattern",
        "action",
        "data",
        "targetClass",
        "colorForeground",
        "colorBackground",
        "backgroundDimAmount",
        "disabledAlpha",
        "textAppearance",
        "textAppearanceInverse",
        "textColorPrimary",
        "textColorPrimaryDisableOnly",
        "textColorSecondary",
        "textColorPrimaryInverse",
        "textColorSecondaryInverse",
        "textColorPrimaryNoDisable",
        "textColorSecondaryNoDisable",
        "textColorPrimaryInverseNoDisable",
        "textColorSecondaryInverseNoDisable",
        "textColorHintInverse",
        "textAppearanceLarge",
        "textAppearanceMedium",
        "textAppearanceSmall",
        "textAppearanceLargeInverse",
        "textAppearanceMediumInverse",
        "textAppearanceSmallInverse",
        "textCheckMark",
        "textCheckMarkInverse",
        "buttonStyle",
        "buttonStyleSmall",
        "buttonStyleInset",
        "buttonStyleToggle",
        "galleryItemBackground",
        "listPreferredItemHeight",
        "expandableListPreferredItemPaddingLeft",
        "expandableListPreferredChildPaddingLeft",
        "expandableListPreferredItemIndicatorLeft",
        "expandableListPreferredItemIndicatorRight",
        "expandableListPreferredChildIndicatorLeft",
        "expandableListPreferredChildIndicatorRight",
        "windowBackground",
        "windowFrame",
        "windowNoTitle",
        "windowIsFloating",
        "windowIsTranslucent",
        "windowContentOverlay",
        "windowTitleSize",
        "windowTitleStyle",
        "windowTitleBackgroundStyle",
        "alertDialogStyle",
        "panelBackground",
        "panelFullBackground",
        "panelColorForeground",
        "panelColorBackground",
        "panelTextAppearance",
        "scrollbarSize",
        "scrollbarThumbHorizontal",
        "scrollbarThumbVertical",
        "scrollbarTrackHorizontal",
        "scrollbarTrackVertical",
        "scrollbarAlwaysDrawHorizontalTrack",
        "scrollbarAlwaysDrawVerticalTrack",
        "absListViewStyle",
        "autoCompleteTextViewStyle",
        "checkboxStyle",
        "dropDownListViewStyle",
        "editTextStyle",
        "expandableListViewStyle",
        "galleryStyle",
        "gridViewStyle",
        "imageButtonStyle",
        "imageWellStyle",
        "listViewStyle",
        "listViewWhiteStyle",
        "popupWindowStyle",
        "progressBarStyle",
        "progressBarStyleHorizontal",
        "progressBarStyleSmall",
        "progressBarStyleLarge",
        "seekBarStyle",
        "ratingBarStyle",
        "ratingBarStyleSmall",
        "radioButtonStyle",
        "scrollbarStyle",
        "scrollViewStyle",
        "spinnerStyle",
        "starStyle",
        "tabWidgetStyle",
        "textViewStyle",
        "webViewStyle",
        "dropDownItemStyle",
        "spinnerDropDownItemStyle",
        "dropDownHintAppearance",
        "spinnerItemStyle",
        "mapViewStyle",
        "preferenceScreenStyle",
        "preferenceCategoryStyle",
        "preferenceInformationStyle",
        "preferenceStyle",
        "checkBoxPreferenceStyle",
        "yesNoPreferenceStyle",
        "dialogPreferenceStyle",
        "editTextPreferenceStyle",
        "ringtonePreferenceStyle",
        "preferenceLayoutChild",
        "textSize",
        "typeface",
        "textStyle",
        "textColor",
        "textColorHighlight",
        "textColorHint",
        "textColorLink",
        "state_focused",
        "state_window_focused",
        "state_enabled",
        "state_checkable",
        "state_checked",
        "state_selected",
        "state_active",
        "state_single",
        "state_first",
        "state_middle",
        "state_last",
        "state_pressed",
        "state_expanded",
        "state_empty",
        "state_above_anchor",
        "ellipsize",
        "x",
        "y",
        "windowAnimationStyle",
        "gravity",
        "autoLink",
        "linksClickable",
        "entries",
        "layout_gravity",
        "windowEnterAnimation",
        "windowExitAnimation",
        "windowShowAnimation",
        "windowHideAnimation",
        "activityOpenEnterAnimation",
        "activityOpenExitAnimation",
        "activityCloseEnterAnimation",
        "activityCloseExitAnimation",
        "taskOpenEnterAnimation",
        "taskOpenExitAnimation",
        "taskCloseEnterAnimation",
        "taskCloseExitAnimation",
        "taskToFrontEnterAnimation",
        "taskToFrontExitAnimation",
        "taskToBackEnterAnimation",
        "taskToBackExitAnimation",
        "orientation",
        "keycode",
        "fullDark",
        "topDark",
        "centerDark",
        "bottomDark",
        "fullBright",
        "topBright",
        "centerBright",
        "bottomBright",
        "bottomMedium",
        "centerMedium",
        "id",
        "tag",
        "scrollX",
        "scrollY",
        "background",
        "padding",
        "paddingLeft",
        "paddingTop",
        "paddingRight",
        "paddingBottom",
        "focusable",
        "focusableInTouchMode",
        "visibility",
        "fitsSystemWindows",
        "scrollbars",
        "fadingEdge",
        "fadingEdgeLength",
        "nextFocusLeft",
        "nextFocusRight",
        "nextFocusUp",
        "nextFocusDown",
        "clickable",
        "longClickable",
        "saveEnabled",
        "drawingCacheQuality",
        "duplicateParentState",
        "clipChildren",
        "clipToPadding",
        "layoutAnimation",
        "animationCache",
        "persistentDrawingCache",
        "alwaysDrawnWithCache",
        "addStatesFromChildren",
        "descendantFocusability",
        "layout",
        "inflatedId",
        "layout_width",
        "layout_height",
        "layout_margin",
        "layout_marginLeft",
        "layout_marginTop",
        "layout_marginRight",
        "layout_marginBottom",
        "listSelector",
        "drawSelectorOnTop",
        "stackFromBottom",
        "scrollingCache",
        "textFilterEnabled",
        "transcriptMode",
        "cacheColorHint",
        "dial",
        "hand_hour",
        "hand_minute",
        "format",
        "checked",
        "button",
        "checkMark",
        "foreground",
        "measureAllChildren",
        "groupIndicator",
        "childIndicator",
        "indicatorLeft",
        "indicatorRight",
        "childIndicatorLeft",
        "childIndicatorRight",
        "childDivider",
        "animationDuration",
        "spacing",
        "horizontalSpacing",
        "verticalSpacing",
        "stretchMode",
        "columnWidth",
        "numColumns",
        "src",
        "antialias",
        "filter",
        "dither",
        "scaleType",
        "adjustViewBounds",
        "maxWidth",
        "maxHeight",
        "tint",
        "baselineAlignBottom",
        "cropToPadding",
        "textOn",
        "textOff",
        "baselineAligned",
        "baselineAlignedChildIndex",
        "weightSum",
        "divider",
        "dividerHeight",
        "choiceMode",
        "itemTextAppearance",
        "horizontalDivider",
        "verticalDivider",
        "headerBackground",
        "itemBackground",
        "itemIconDisabledAlpha",
        "rowHeight",
        "maxRows",
        "maxItemsPerRow",
        "moreIcon",
        "max",
        "progress",
        "secondaryProgress",
        "indeterminate",
        "indeterminateOnly",
        "indeterminateDrawable",
        "progressDrawable",
        "indeterminateDuration",
        "indeterminateBehavior",
        "minWidth",
        "minHeight",
        "interpolator",
        "thumb",
        "thumbOffset",
        "numStars",
        "rating",
        "stepSize",
        "isIndicator",
        "checkedButton",
        "stretchColumns",
        "shrinkColumns",
        "collapseColumns",
        "layout_column",
        "layout_span",
        "bufferType",
        "text",
        "hint",
        "textScaleX",
        "cursorVisible",
        "maxLines",
        "lines",
        "height",
        "minLines",
        "maxEms",
        "ems",
        "width",
        "minEms",
        "scrollHorizontally",
        "password",
        "singleLine",
        "selectAllOnFocus",
        "includeFontPadding",
        "maxLength",
        "shadowColor",
        "shadowDx",
        "shadowDy",
        "shadowRadius",
        "numeric",
        "digits",
        "phoneNumber",
        "inputMethod",
        "capitalize",
        "autoText",
        "editable",
        "freezesText",
        "drawableTop",
        "drawableBottom",
        "drawableLeft",
        "drawableRight",
        "drawablePadding",
        "completionHint",
        "completionHintView",
        "completionThreshold",
        "dropDownSelector",
        "popupBackground",
        "inAnimation",
        "outAnimation",
        "flipInterval",
        "fillViewport",
        "prompt",
        "startYear",
        "endYear",
        "mode",
        "layout_x",
        "layout_y",
        "layout_weight",
        "layout_toLeftOf",
        "layout_toRightOf",
        "layout_above",
        "layout_below",
        "layout_alignBaseline",
        "layout_alignLeft",
        "layout_alignTop",
        "layout_alignRight",
        "layout_alignBottom",
        "layout_alignParentLeft",
        "layout_alignParentTop",
        "layout_alignParentRight",
        "layout_alignParentBottom",
        "layout_centerInParent",
        "layout_centerHorizontal",
        "layout_centerVertical",
        "layout_alignWithParentIfMissing",
        "layout_scale",
        "visible",
        "variablePadding",
        "constantSize",
        "oneshot",
        "duration",
        "drawable",
        "shape",
        "innerRadiusRatio",
        "thicknessRatio",
        "startColor",
        "endColor",
        "useLevel",
        "angle",
        "type",
        "centerX",
        "centerY",
        "gradientRadius",
        "color",
        "dashWidth",
        "dashGap",
        "radius",
        "topLeftRadius",
        "topRightRadius",
        "bottomLeftRadius",
        "bottomRightRadius",
        "left",
        "top",
        "right",
        "bottom",
        "minLevel",
        "maxLevel",
        "fromDegrees",
        "toDegrees",
        "pivotX",
        "pivotY",
        "insetLeft",
        "insetRight",
        "insetTop",
        "insetBottom",
        "shareInterpolator",
        "fillBefore",
        "fillAfter",
        "startOffset",
        "repeatCount",
        "repeatMode",
        "zAdjustment",
        "fromXScale",
        "toXScale",
        "fromYScale",
        "toYScale",
        "fromXDelta",
        "toXDelta",
        "fromYDelta",
        "toYDelta",
        "fromAlpha",
        "toAlpha",
        "delay",
        "animation",
        "animationOrder",
        "columnDelay",
        "rowDelay",
        "direction",
        "directionPriority",
        "factor",
        "cycles",
        "searchMode",
        "searchSuggestAuthority",
        "searchSuggestPath",
        "searchSuggestSelection",
        "searchSuggestIntentAction",
        "searchSuggestIntentData",
        "queryActionMsg",
        "suggestActionMsg",
        "suggestActionMsgColumn",
        "menuCategory",
        "orderInCategory",
        "checkableBehavior",
        "title",
        "titleCondensed",
        "alphabeticShortcut",
        "numericShortcut",
        "checkable",
        "selectable",
        "orderingFromXml",
        "key",
        "summary",
        "order",
        "widgetLayout",
        "dependency",
        "defaultValue",
        "shouldDisableView",
        "summaryOn",
        "summaryOff",
        "disableDependentsState",
        "dialogTitle",
        "dialogMessage",
        "dialogIcon",
        "positiveButtonText",
        "negativeButtonText",
        "dialogLayout",
        "entryValues",
        "ringtoneType",
        "showDefault",
        "showSilent",
        "scaleWidth",
        "scaleHeight",
        "scaleGravity",
        "ignoreGravity",
        "foregroundGravity",
        "tileMode",
        "targetActivity",
        "alwaysRetainTaskState",
        "allowTaskReparenting",
        "searchButtonText",
        "colorForegroundInverse",
        "textAppearanceButton",
        "listSeparatorTextViewStyle",
        "streamType",
        "clipOrientation",
        "centerColor",
        "minSdkVersion",
        "windowFullscreen",
        "unselectedAlpha",
        "progressBarStyleSmallTitle",
        "ratingBarStyleIndicator",
        "apiKey",
        "textColorTertiary",
        "textColorTertiaryInverse",
        "listDivider",
        "soundEffectsEnabled",
        "keepScreenOn",
        "lineSpacingExtra",
        "lineSpacingMultiplier",
        "listChoiceIndicatorSingle",
        "listChoiceIndicatorMultiple",
        "versionCode",
        "versionName",
        "marqueeRepeatLimit",
        "windowNoDisplay",
        "backgroundDimEnabled",
        "inputType",
        "isDefault",
        "windowDisablePreview",
        "privateImeOptions",
        "editorExtras",
        "settingsActivity",
        "fastScrollEnabled",
        "reqTouchScreen",
        "reqKeyboardType",
        "reqHardKeyboard",
        "reqNavigation",
        "windowSoftInputMode",
        "imeFullscreenBackground",
        "noHistory",
        "headerDividersEnabled",
        "footerDividersEnabled",
        "candidatesTextStyleSpans",
        "smoothScrollbar",
        "reqFiveWayNav",
        "keyBackground",
        "keyTextSize",
        "labelTextSize",
        "keyTextColor",
        "keyPreviewLayout",
        "keyPreviewOffset",
        "keyPreviewHeight",
        "verticalCorrection",
        "popupLayout",
        "state_long_pressable",
        "keyWidth",
        "keyHeight",
        "horizontalGap",
        "verticalGap",
        "rowEdgeFlags",
        "codes",
        "popupKeyboard",
        "popupCharacters",
        "keyEdgeFlags",
        "isModifier",
        "isSticky",
        "isRepeatable",
        "iconPreview",
        "keyOutputText",
        "keyLabel",
        "keyIcon",
        "keyboardMode",
        "isScrollContainer",
        "fillEnabled",
        "updatePeriodMillis",
        "initialLayout",
        "voiceSearchMode",
        "voiceLanguageModel",
        "voicePromptText",
        "voiceLanguage",
        "voiceMaxResults",
        "bottomOffset",
        "topOffset",
        "allowSingleTap",
        "handle",
        "content",
        "animateOnClick",
        "configure",
        "hapticFeedbackEnabled",
        "innerRadius",
        "thickness",
        "sharedUserLabel",
        "dropDownWidth",
        "dropDownAnchor",
        "imeOptions",
        "imeActionLabel",
        "imeActionId",
        "UNKNOWN",
        "imeExtractEnterAnimation",
        "imeExtractExitAnimation",
        "tension",
        "extraTension",
        "anyDensity",
        "searchSuggestThreshold",
        "includeInGlobalSearch",
        "onClick",
        "targetSdkVersion",
        "maxSdkVersion",
        "testOnly",
        "contentDescription",
        "gestureStrokeWidth",
        "gestureColor",
        "uncertainGestureColor",
        "fadeOffset",
        "fadeDuration",
        "gestureStrokeType",
        "gestureStrokeLengthThreshold",
        "gestureStrokeSquarenessThreshold",
        "gestureStrokeAngleThreshold",
        "eventsInterceptionEnabled",
        "fadeEnabled",
        "backupAgent",
        "allowBackup",
        "glEsVersion",
        "queryAfterZeroResults",
        "dropDownHeight",
        "smallScreens",
        "normalScreens",
        "largeScreens",
        "progressBarStyleInverse",
        "progressBarStyleSmallInverse",
        "progressBarStyleLargeInverse",
        "searchSettingsDescription",
        "textColorPrimaryInverseDisableOnly",
        "autoUrlDetect",
        "resizeable",
        "required",
        "accountType",
        "contentAuthority",
        "userVisible",
        "windowShowWallpaper",
        "wallpaperOpenEnterAnimation",
        "wallpaperOpenExitAnimation",
        "wallpaperCloseEnterAnimation",
        "wallpaperCloseExitAnimation",
        "wallpaperIntraOpenEnterAnimation",
        "wallpaperIntraOpenExitAnimation",
        "wallpaperIntraCloseEnterAnimation",
        "wallpaperIntraCloseExitAnimation",
        "supportsUploading",
        "killAfterRestore",
        "restoreNeedsApplication",
        "smallIcon",
        "accountPreferences",
        "textAppearanceSearchResultSubtitle",
        "textAppearanceSearchResultTitle",
        "summaryColumn",
        "detailColumn",
        "detailSocialSummary",
        "thumbnail",
        "detachWallpaper",
        "finishOnCloseSystemDialogs",
        "scrollbarFadeDuration",
        "scrollbarDefaultDelayBeforeFade",
        "fadeScrollbars",
        "colorBackgroundCacheHint",
        "dropDownHorizontalOffset",
        "dropDownVerticalOffset",
        "quickContactBadgeStyleWindowSmall",
        "quickContactBadgeStyleWindowMedium",
        "quickContactBadgeStyleWindowLarge",
        "quickContactBadgeStyleSmallWindowSmall",
        "quickContactBadgeStyleSmallWindowMedium",
        "quickContactBadgeStyleSmallWindowLarge",
        "author",
        "autoStart",
        "expandableListViewWhiteStyle",
        "installLocation",
        "vmSafeMode",
        "webTextViewStyle",
        "restoreAnyVersion",
        "tabStripLeft",
        "tabStripRight",
        "tabStripEnabled",
        "logo",
        "xlargeScreens",
        "immersive",
        "overScrollMode",
        "overScrollHeader",
        "overScrollFooter",
        "filterTouchesWhenObscured",
        "textSelectHandleLeft",
        "textSelectHandleRight",
        "textSelectHandle",
        "textSelectHandleWindowStyle",
        "popupAnimationStyle",
        "screenSize",
        "screenDensity",
        "allContactsName",
        "windowActionBar",
        "actionBarStyle",
        "navigationMode",
        "displayOptions",
        "subtitle",
        "customNavigationLayout",
        "hardwareAccelerated",
        "measureWithLargestChild",
        "animateFirstView",
        "dropDownSpinnerStyle",
        "actionDropDownStyle",
        "actionButtonStyle",
        "showAsAction",
        "previewImage",
        "actionModeBackground",
        "actionModeCloseDrawable",
        "windowActionModeOverlay",
        "valueFrom",
        "valueTo",
        "valueType",
        "propertyName",
        "ordering",
        "fragment",
        "windowActionBarOverlay",
        "fragmentOpenEnterAnimation",
        "fragmentOpenExitAnimation",
        "fragmentCloseEnterAnimation",
        "fragmentCloseExitAnimation",
        "fragmentFadeEnterAnimation",
        "fragmentFadeExitAnimation",
        "actionBarSize",
        "imeSubtypeLocale",
        "imeSubtypeMode",
        "imeSubtypeExtraValue",
        "splitMotionEvents",
        "listChoiceBackgroundIndicator",
        "spinnerMode",
        "animateLayoutChanges",
        "actionBarTabStyle",
        "actionBarTabBarStyle",
        "actionBarTabTextStyle",
        "actionOverflowButtonStyle",
        "actionModeCloseButtonStyle",
        "titleTextStyle",
        "subtitleTextStyle",
        "iconifiedByDefault",
        "actionLayout",
        "actionViewClass",
        "activatedBackgroundIndicator",
        "state_activated",
        "listPopupWindowStyle",
        "popupMenuStyle",
        "textAppearanceLargePopupMenu",
        "textAppearanceSmallPopupMenu",
        "breadCrumbTitle",
        "breadCrumbShortTitle",
        "listDividerAlertDialog",
        "textColorAlertDialogListItem",
        "loopViews",
        "dialogTheme",
        "alertDialogTheme",
        "dividerVertical",
        "homeAsUpIndicator",
        "enterFadeDuration",
        "exitFadeDuration",
        "selectableItemBackground",
        "autoAdvanceViewId",
        "useIntrinsicSizeAsMinimum",
        "actionModeCutDrawable",
        "actionModeCopyDrawable",
        "actionModePasteDrawable",
        "textEditPasteWindowLayout",
        "textEditNoPasteWindowLayout",
        "textIsSelectable",
        "windowEnableSplitTouch",
        "indeterminateProgressStyle",
        "progressBarPadding",
        "animationResolution",
        "state_accelerated",
        "baseline",
        "homeLayout",
        "opacity",
        "alpha",
        "transformPivotX",
        "transformPivotY",
        "translationX",
        "translationY",
        "scaleX",
        "scaleY",
        "rotation",
        "rotationX",
        "rotationY",
        "showDividers",
        "dividerPadding",
        "borderlessButtonStyle",
        "dividerHorizontal",
        "itemPadding",
        "buttonBarStyle",
        "buttonBarButtonStyle",
        "segmentedButtonStyle",
        "staticWallpaperPreview",
        "allowParallelSyncs",
        "isAlwaysSyncable",
        "verticalScrollbarPosition",
        "fastScrollAlwaysVisible",
        "fastScrollThumbDrawable",
        "fastScrollPreviewBackgroundLeft",
        "fastScrollPreviewBackgroundRight",
        "fastScrollTrackDrawable",
        "fastScrollOverlayPosition",
        "customTokens",
        "nextFocusForward",
        "firstDayOfWeek",
        "showWeekNumber",
        "minDate",
        "maxDate",
        "shownWeekCount",
        "selectedWeekBackgroundColor",
        "focusedMonthDateColor",
        "unfocusedMonthDateColor",
        "weekNumberColor",
        "weekSeparatorLineColor",
        "selectedDateVerticalBar",
        "weekDayTextAppearance",
        "dateTextAppearance",
        "UNKNOWN",
        "spinnersShown",
        "calendarViewShown",
        "state_multiline",
        "detailsElementBackground",
        "textColorHighlightInverse",
        "textColorLinkInverse",
        "editTextColor",
        "editTextBackground",
        "horizontalScrollViewStyle",
        "layerType",
        "alertDialogIcon",
        "windowMinWidthMajor",
        "windowMinWidthMinor",
        "queryHint",
        "fastScrollTextColor",
        "largeHeap",
        "windowCloseOnTouchOutside",
        "datePickerStyle",
        "calendarViewStyle",
        "textEditSidePasteWindowLayout",
        "textEditSideNoPasteWindowLayout",
        "actionMenuTextAppearance",
        "actionMenuTextColor",
        "textCursorDrawable",
        "resizeMode",
        "requiresSmallestWidthDp",
        "compatibleWidthLimitDp",
        "largestWidthLimitDp",
        "state_hovered",
        "state_drag_can_accept",
        "state_drag_hovered",
        "stopWithTask",
        "switchTextOn",
        "switchTextOff",
        "switchPreferenceStyle",
        "switchTextAppearance",
        "track",
        "switchMinWidth",
        "switchPadding",
        "thumbTextPadding",
        "textSuggestionsWindowStyle",
        "textEditSuggestionItemLayout",
        "rowCount",
        "rowOrderPreserved",
        "columnCount",
        "columnOrderPreserved",
        "useDefaultMargins",
        "alignmentMode",
        "layout_row",
        "layout_rowSpan",
        "layout_columnSpan",
        "actionModeSelectAllDrawable",
        "isAuxiliary",
        "accessibilityEventTypes",
        "packageNames",
        "accessibilityFeedbackType",
        "notificationTimeout",
        "accessibilityFlags",
        "canRetrieveWindowContent",
        "listPreferredItemHeightLarge",
        "listPreferredItemHeightSmall",
        "actionBarSplitStyle",
        "actionProviderClass",
        "backgroundStacked",
        "backgroundSplit",
        "textAllCaps",
        "colorPressedHighlight",
        "colorLongPressedHighlight",
        "colorFocusedHighlight",
        "colorActivatedHighlight",
        "colorMultiSelectHighlight",
        "drawableStart",
        "drawableEnd",
        "actionModeStyle",
        "minResizeWidth",
        "minResizeHeight",
        "actionBarWidgetTheme",
        "uiOptions",
        "subtypeLocale",
        "subtypeExtraValue",
        "actionBarDivider",
        "actionBarItemBackground",
        "actionModeSplitBackground",
        "textAppearanceListItem",
        "textAppearanceListItemSmall",
        "targetDescriptions",
        "directionDescriptions",
        "overridesImplicitlyEnabledSubtype",
        "listPreferredItemPaddingLeft",
        "listPreferredItemPaddingRight",
        "requiresFadingEdge",
        "publicKey",
        "parentActivityName",
        "UNKNOWN",
        "isolatedProcess",
        "importantForAccessibility",
        "keyboardLayout",
        "fontFamily",
        "mediaRouteButtonStyle",
        "mediaRouteTypes",
        "supportsRtl",
        "textDirection",
        "textAlignment",
        "layoutDirection",
        "paddingStart",
        "paddingEnd",
        "layout_marginStart",
        "layout_marginEnd",
        "layout_toStartOf",
        "layout_toEndOf",
        "layout_alignStart",
        "layout_alignEnd",
        "layout_alignParentStart",
        "layout_alignParentEnd",
        "listPreferredItemPaddingStart",
        "listPreferredItemPaddingEnd",
        "singleUser",
        "presentationTheme",
        "subtypeId",
        "initialKeyguardLayout",
        "UNKNOWN",
        "widgetCategory",
        "permissionGroupFlags",
        "labelFor",
        "permissionFlags",
        "checkedTextViewStyle",
        "showOnLockScreen",
        "format12Hour",
        "format24Hour",
        "timeZone",
        "mipMap",
        "mirrorForRtl",
        "windowOverscan",
        "requiredForAllUsers",
        "indicatorStart",
        "indicatorEnd",
        "childIndicatorStart",
        "childIndicatorEnd",
        "restrictedAccountType",
        "requiredAccountType",
        "canRequestTouchExplorationMode",
        "canRequestEnhancedWebAccessibility",
        "canRequestFilterKeyEvents",
        "layoutMode",
        "keySet",
        "targetId",
        "fromScene",
        "toScene",
        "transition",
        "transitionOrdering",
        "fadingMode",
        "startDelay",
        "ssp",
        "sspPrefix",
        "sspPattern",
        "addPrintersActivity",
        "vendor",
        "category",
        "isAsciiCapable",
        "autoMirrored",
        "supportsSwitchingToNextInputMethod",
        "requireDeviceUnlock",
        "apduServiceBanner",
        "accessibilityLiveRegion",
        "windowTranslucentStatus",
        "windowTranslucentNavigation",
        "advancedPrintOptionsActivity",
        "banner",
        "windowSwipeToDismiss",
        "isGame",
        "allowEmbedded",
        "setupActivity",
        "fastScrollStyle",
        "windowContentTransitions",
        "windowContentTransitionManager",
        "translationZ",
        "tintMode",
        "controlX1",
        "controlY1",
        "controlX2",
        "controlY2",
        "transitionName",
        "transitionGroup",
        "viewportWidth",
        "viewportHeight",
        "fillColor",
        "pathData",
        "strokeColor",
        "strokeWidth",
        "trimPathStart",
        "trimPathEnd",
        "trimPathOffset",
        "strokeLineCap",
        "strokeLineJoin",
        "strokeMiterLimit",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "colorControlNormal",
        "colorControlActivated",
        "colorButtonNormal",
        "colorControlHighlight",
        "persistableMode",
        "titleTextAppearance",
        "subtitleTextAppearance",
        "slideEdge",
        "actionBarTheme",
        "textAppearanceListItemSecondary",
        "colorPrimary",
        "colorPrimaryDark",
        "colorAccent",
        "nestedScrollingEnabled",
        "windowEnterTransition",
        "windowExitTransition",
        "windowSharedElementEnterTransition",
        "windowSharedElementExitTransition",
        "windowAllowReturnTransitionOverlap",
        "windowAllowEnterTransitionOverlap",
        "sessionService",
        "stackViewStyle",
        "switchStyle",
        "elevation",
        "excludeId",
        "excludeClass",
        "hideOnContentScroll",
        "actionOverflowMenuStyle",
        "documentLaunchMode",
        "maxRecents",
        "autoRemoveFromRecents",
        "stateListAnimator",
        "toId",
        "fromId",
        "reversible",
        "splitTrack",
        "targetName",
        "excludeName",
        "matchOrder",
        "windowDrawsSystemBarBackgrounds",
        "statusBarColor",
        "navigationBarColor",
        "contentInsetStart",
        "contentInsetEnd",
        "contentInsetLeft",
        "contentInsetRight",
        "paddingMode",
        "layout_rowWeight",
        "layout_columnWeight",
        "translateX",
        "translateY",
        "selectableItemBackgroundBorderless",
        "elegantTextHeight",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
        "windowTransitionBackgroundFadeDuration",
        "overlapAnchor",
        "progressTint",
        "progressTintMode",
        "progressBackgroundTint",
        "progressBackgroundTintMode",
        "secondaryProgressTint",
        "secondaryProgressTintMode",
        "indeterminateTint",
        "indeterminateTintMode",
        "backgroundTint",
        "backgroundTintMode",
        "foregroundTint",
        "foregroundTintMode",
        "buttonTint",
        "buttonTintMode",
        "thumbTint",
        "thumbTintMode",
        "fullBackupOnly",
        "propertyXName",
        "propertyYName",
        "relinquishTaskIdentity",
        "tileModeX",
        "tileModeY",
        "actionModeShareDrawable",
        "actionModeFindDrawable",
        "actionModeWebSearchDrawable",
        "transitionVisibilityMode",
        "minimumHorizontalAngle",
        "minimumVerticalAngle",
        "maximumAngle",
        "searchViewStyle",
        "closeIcon",
        "goIcon",
        "searchIcon",
        "voiceIcon",
        "commitIcon",
        "suggestionRowLayout",
        "queryBackground",
        "submitBackground",
        "buttonBarPositiveButtonStyle",
        "buttonBarNeutralButtonStyle",
        "buttonBarNegativeButtonStyle",
        "popupElevation",
        "actionBarPopupTheme",
        "multiArch",
        "touchscreenBlocksFocus",
        "windowElevation",
        "launchTaskBehindTargetAnimation",
        "launchTaskBehindSourceAnimation",
        "restrictionType",
        "dayOfWeekBackground",
        "dayOfWeekTextAppearance",
        "headerMonthTextAppearance",
        "headerDayOfMonthTextAppearance",
        "headerYearTextAppearance",
        "yearListItemTextAppearance",
        "yearListSelectorColor",
        "calendarTextColor",
        "recognitionService",
        "timePickerStyle",
        "timePickerDialogTheme",
        "headerTimeTextAppearance",
        "headerAmPmTextAppearance",
        "numbersTextColor",
        "numbersBackgroundColor",
        "numbersSelectorColor",
        "amPmTextColor",
        "amPmBackgroundColor",
        "UNKNOWN",
        "checkMarkTint",
        "checkMarkTintMode",
        "popupTheme",
        "toolbarStyle",
        "windowClipToOutline",
        "datePickerDialogTheme",
        "showText",
        "windowReturnTransition",
        "windowReenterTransition",
        "windowSharedElementReturnTransition",
        "windowSharedElementReenterTransition",
        "resumeWhilePausing",
        "datePickerMode",
        "timePickerMode",
        "inset",
        "letterSpacing",
        "fontFeatureSettings",
        "outlineProvider",
        "contentAgeHint",
        "country",
        "windowSharedElementsUseOverlay",
        "reparent",
        "reparentWithOverlay",
        "ambientShadowAlpha",
        "spotShadowAlpha",
        "navigationIcon",
        "navigationContentDescription",
        "fragmentExitTransition",
        "fragmentEnterTransition",
        "fragmentSharedElementEnterTransition",
        "fragmentReturnTransition",
        "fragmentSharedElementReturnTransition",
        "fragmentReenterTransition",
        "fragmentAllowEnterTransitionOverlap",
        "fragmentAllowReturnTransitionOverlap",
        "patternPathData",
        "strokeAlpha",
        "fillAlpha",
        "windowActivityTransitions",
        "colorEdgeEffect",
        "resizeClip",
        "collapseContentDescription",
        "accessibilityTraversalBefore",
        "accessibilityTraversalAfter",
        "dialogPreferredPadding",
        "searchHintIcon",
        "revisionCode",
        "drawableTint",
        "drawableTintMode",
        "fraction",
        "trackTint",
        "trackTintMode",
        "start",
        "end",
        "breakStrategy",
        "hyphenationFrequency",
        "allowUndo",
        "windowLightStatusBar",
        "numbersInnerTextColor",
        "colorBackgroundFloating",
        "titleTextColor",
        "subtitleTextColor",
        "thumbPosition",
        "scrollIndicators",
        "contextClickable",
        "fingerprintAuthDrawable",
        "logoDescription",
        "extractNativeLibs",
        "fullBackupContent",
        "usesCleartextTraffic",
        "lockTaskMode",
        "autoVerify",
        "showForAllUsers",
        "supportsAssist",
        "supportsLaunchVoiceAssistFromKeyguard",
        "listMenuViewStyle",
        "subMenuArrow",
        "defaultWidth",
        "defaultHeight",
        "resizeableActivity",
        "supportsPictureInPicture",
        "titleMargin",
        "titleMarginStart",
        "titleMarginEnd",
        "titleMarginTop",
        "titleMarginBottom",
        "maxButtonHeight",
        "buttonGravity",
        "collapseIcon",
        "level",
        "contextPopupMenuStyle",
        "textAppearancePopupMenuHeader",
        "windowBackgroundFallback",
        "defaultToDeviceProtectedStorage",
        "directBootAware",
        "preferenceFragmentStyle",
        "canControlMagnification",
        "languageTag",
        "pointerIcon",
        "tickMark",
        "tickMarkTint",
        "tickMarkTintMode",
        "canPerformGestures",
        "externalService",
        "supportsLocalInteraction",
        "startX",
        "startY",
        "endX",
        "endY",
        "offset",
        "use32bitAbi",
        "bitmap",
        "hotSpotX",
        "hotSpotY",
        "version",
        "backupInForeground",
        "countDown",
        "canRecord",
        "tunerCount",
        "fillType",
        "popupEnterTransition",
        "popupExitTransition",
        "forceHasOverlappingRendering",
        "contentInsetStartWithNavigation",
        "contentInsetEndWithActions",
        "numberPickerStyle",
        "enableVrMode",
        "UNKNOWN",
        "networkSecurityConfig",
        "shortcutId",
        "shortcutShortLabel",
        "shortcutLongLabel",
        "shortcutDisabledMessage",
        "roundIcon",
        "contextUri",
        "contextDescription",
        "showMetadataInPreview",
        "colorSecondary",
    ]
