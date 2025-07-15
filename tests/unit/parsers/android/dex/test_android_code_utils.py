from launchpad.parsers.android.dex.android_code_utils import AndroidCodeUtils


class TestAndroidCodeUtils:
    def test_class_signature_to_fqn(self) -> None:
        assert AndroidCodeUtils.class_signature_to_fqn("Lcom/example/MyClass;") == "com.example.MyClass"
        assert AndroidCodeUtils.class_signature_to_fqn("Ljava/lang/String;") == "java.lang.String"
        assert AndroidCodeUtils.class_signature_to_fqn("Landroid/app/Activity;") == "android.app.Activity"

        assert AndroidCodeUtils.class_signature_to_fqn("com/example/MyClass") == "com.example.MyClass"

    def test_fqn_to_class_signature(self) -> None:
        assert AndroidCodeUtils.fqn_to_class_signature("com.example.MyClass") == "Lcom/example/MyClass;"
        assert AndroidCodeUtils.fqn_to_class_signature("java.lang.String") == "Ljava/lang/String;"
        assert AndroidCodeUtils.fqn_to_class_signature("android.app.Activity") == "Landroid/app/Activity;"

    def test_remove_kotlin_suffix_from_signature(self) -> None:
        assert (
            AndroidCodeUtils.remove_kotlin_suffix_from_signature("Lcom/example/MyClassKt;") == "Lcom/example/MyClass;"
        )
        assert AndroidCodeUtils.remove_kotlin_suffix_from_signature("Lcom/example/MyClass;") == "Lcom/example/MyClass;"
        assert AndroidCodeUtils.remove_kotlin_suffix_from_signature("Lcom/example/KtClass;") == "Lcom/example/KtClass;"

    def test_remove_kotlin_suffix_from_fqn(self) -> None:
        assert AndroidCodeUtils.remove_kotlin_suffix_from_fqn("com.example.MyClassKt") == "com.example.MyClass"
        assert AndroidCodeUtils.remove_kotlin_suffix_from_fqn("com.example.MyClass") == "com.example.MyClass"
        assert AndroidCodeUtils.remove_kotlin_suffix_from_fqn("com.example.KtClass") == "com.example.KtClass"
