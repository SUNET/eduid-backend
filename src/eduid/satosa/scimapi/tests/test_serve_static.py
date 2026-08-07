from pathlib import Path

from satosa.context import Context

from eduid.satosa.scimapi.serve_static import ServeStatic

__author__ = "lundberg"


def make_service(static_dir: Path) -> ServeStatic:
    config = {"locations": {"static": str(static_dir)}}
    return ServeStatic(config=config, name="ServeStatic", base_url="https://example.com")


def make_context(path: str) -> Context:
    context = Context()
    context.path = path
    return context


class TestServeStatic:
    def test_serves_file_within_location(self, tmp_path: Path) -> None:
        static_dir = tmp_path / "static"
        static_dir.mkdir()
        (static_dir / "hello.txt").write_bytes(b"hello world")

        service = make_service(static_dir)
        response = service._handle(make_context("static/hello.txt"))
        assert response.status == "200 OK"
        assert response.message == b"hello world"

    def test_rejects_path_traversal_to_sibling_file(self, tmp_path: Path) -> None:
        """
        Regression test: `../` in the requested path must not escape the
        configured static directory (arbitrary file read).
        """
        static_dir = tmp_path / "static"
        static_dir.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_bytes(b"top secret")

        service = make_service(static_dir)
        response = service._handle(make_context("static/../secret.txt"))
        assert response.status == "404 Not Found"
        assert b"top secret" not in response.message

    def test_rejects_deeply_nested_path_traversal(self, tmp_path: Path) -> None:
        static_dir = tmp_path / "jail" / "static"
        static_dir.mkdir(parents=True)
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"outside the jail")

        service = make_service(static_dir)
        # static_dir is tmp_path/jail/static; "../../" walks static -> jail -> tmp_path
        response = service._handle(make_context("static/../../outside.txt"))
        assert response.status == "404 Not Found"
        assert b"outside the jail" not in response.message
