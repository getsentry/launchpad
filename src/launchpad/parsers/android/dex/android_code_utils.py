import re


class AndroidCodeUtils:
    @staticmethod
    def class_signature_to_fqn(class_signature: str) -> str:
        # Remove leading 'L' and trailing ';' if they exist
        if class_signature.startswith("L"):
            class_signature = class_signature[1:]
        if class_signature.endswith(";"):
            class_signature = class_signature[:-1]

        return class_signature.replace("/", ".")

    @staticmethod
    def fqn_to_class_signature(fqn: str) -> str:
        fqn = fqn.replace(".", "/")
        return f"L{fqn};"

    @staticmethod
    def remove_kotlin_suffix_from_signature(class_signature: str) -> str:
        return re.sub(r"Kt(?=[$/;])", "", class_signature)

    @staticmethod
    def remove_kotlin_suffix_from_fqn(fqn: str) -> str:
        return re.sub(r"Kt(?=[$.]|\b)", "", fqn)
