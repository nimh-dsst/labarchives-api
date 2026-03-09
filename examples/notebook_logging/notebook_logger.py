"""
Jupyter Notebook Logger

Logs Jupyter notebook runs (cell info, outputs, matplotlib figures) to LabArchives.

LabArchives path structure:
    {notebook}/Notebook Log/{email}/{iso8601_timestamp}/
        Notebook Run Details   (page)
            ├── Cell Info       (text entry)
            ├── Tags            (text entry)
            ├── Result          (plain text entry)
            └── Figure 1..N     (AttachmentEntry: PNG)
"""

import html
import os
from datetime import datetime
from io import BytesIO
from mimetypes import guess_type
from typing import Any

from labapi import Client, InsertBehavior, NotebookDirectory, NotebookPage
from labapi.tree.mixins import AbstractTreeContainer
from labapi.user import User

try:
    from IPython import get_ipython
except ImportError:
    get_ipython = None


class NotebookLogger:
    """Logs Jupyter notebook runs and outputs to LabArchives."""

    def __init__(
        self,
        notebook_name: str,
        client: Client | None = None,
        user: User | None = None,
    ) -> None:
        """
        Initialize the logger with Jupyter-friendly auth.

        Displays a clickable auth link in the notebook cell output, then waits
        for the user to authenticate in their browser.

        :param notebook_name: Name of the LabArchives notebook.
        :param client: Optional pre-configured client (loaded from .env if omitted).
        :param user: Optional pre-authenticated User instance.
        """
        self.client = client or Client()
        self.notebook_name = notebook_name
        self.captured_figures: list[bytes] = []
        self._captured_figure_data: dict[int, bytes] = {}
        self.tracked_files: list[str] = []

        # Register IPython display formatter to capture figures as they are shown
        ip = get_ipython()
        if ip:
            try:
                import matplotlib.figure
                import matplotlib.pyplot as plt

                def capture_fig(fig):
                    return self._serialize_figure(fig)

                ip.display_formatter.formatters["image/png"].for_type(
                    matplotlib.figure.Figure, capture_fig
                )

                original_show = plt.show

                def capture_show(*args: Any, **kwargs: Any):
                    # Capture currently open figures before inline backends close them.
                    for fig_num in plt.get_fignums():
                        self._serialize_figure(plt.figure(fig_num))
                    return original_show(*args, **kwargs)

                plt.show = capture_show
            except ImportError:
                pass

        if user is not None:
            self.user = user
            print(f"Using existing authentication for: {self.user.email}")
            return

        auth_url = self.client.generate_auth_url("http://localhost:8089/")

        try:
            from IPython.display import HTML, display

            display(
                HTML(
                    f"<p><strong>Authenticate:</strong> "
                    f'<a href="{auth_url}" target="_blank">'
                    f"Click here to log in to LabArchives</a></p>"
                )
            )
        except ImportError:
            print(f"Authenticate by visiting:\n  {auth_url}")

        print("Waiting for authentication...")
        # Note: This is a blocking call that waits for the redirect on port 8089
        self.user = self.client.collect_auth_response()
        print(f"Authenticated as: {self.user.email}")

    def track_file(self, path: str) -> None:
        """Register a file to be uploaded with the next log() call."""
        abs_path = os.path.abspath(path)
        if not os.path.exists(abs_path):
            print(f"Warning: File {path} not found.")
            return
        if abs_path not in self.tracked_files:
            self.tracked_files.append(abs_path)
            print(f"Tracking file for LabArchives: {path}")

    def _get_or_create_dir(
        self, parent: AbstractTreeContainer, name: str
    ) -> AbstractTreeContainer:
        """Get or create a directory by name under parent."""
        return parent.create(NotebookDirectory, name, if_exists=InsertBehavior.Retain)

    def _capture_figures(self) -> list[bytes]:
        """Capture all open matplotlib figures as PNG bytes."""
        figures = list(self.captured_figures)
        seen_figure_ids = set(self._captured_figure_data)

        try:
            import matplotlib.pyplot as plt
        except ImportError:
            self.captured_figures.clear()
            self._captured_figure_data.clear()
            return figures

        for fig_num in plt.get_fignums():
            fig = plt.figure(fig_num)
            fig_id = id(fig)
            if fig_id in seen_figure_ids:
                continue
            figures.append(self._serialize_figure(fig))
            seen_figure_ids.add(fig_id)

        self.captured_figures.clear()
        self._captured_figure_data.clear()
        return figures

    def _serialize_figure(self, fig: Any) -> bytes:
        """Serialize a matplotlib figure to PNG bytes and cache it once per cycle."""
        figure_id = id(fig)
        cached = self._captured_figure_data.get(figure_id)
        if cached is not None:
            return cached

        buf = BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        data = buf.getvalue()
        self.captured_figures.append(data)
        self._captured_figure_data[figure_id] = data
        return data

    def _capture_cell_info(self) -> dict[str, Any]:
        """Capture recent cell sources and execution count from IPython."""
        ip = get_ipython() if get_ipython else None

        if ip is None:
            return {"source": "(not in IPython)", "execution_count": None}

        history = list(ip.history_manager.get_range(output=False))
        return {
            "execution_count": ip.execution_count,
            "recent_cells": [src for _, _, src in history[-5:]],
        }

    def _capture_last_result(self) -> str:
        """Capture the last cell output value from IPython."""
        ip = get_ipython() if get_ipython else None

        if ip is None:
            return "(no result)"

        result = getattr(ip, "last_execution_result", None)
        if result is not None and result.result is not None:
            return repr(result.result)

        out = ip.user_ns.get("Out", {})
        if out:
            return repr(out[max(out.keys())])

        return "(no result)"

    def log(
        self,
        tags: list[str],
        cell_info: dict[str, Any],
        result: str,
        figures: list[bytes],
        files: list[str] | None = None,
    ) -> None:
        """
        Save a notebook run to LabArchives.

        :param tags: List of string tags for this run.
        :param cell_info: Dict with 'execution_count' and 'recent_cells'.
        :param result: String repr of the last cell output.
        :param figures: List of PNG bytes, one per matplotlib figure.
        :param files: Optional list of file paths to attach.
        """
        from labapi.entry import Attachment

        # Combine explicitly passed files and tracked files, avoiding duplicates
        all_files = set(self.tracked_files)
        if files:
            all_files.update(os.path.abspath(f) for f in files)
        self.tracked_files.clear()

        notebooks = self.user.notebooks
        try:
            notebook = notebooks[self.notebook_name]
        except KeyError:
            available = ", ".join(notebooks.keys())
            raise RuntimeError(
                f"Notebook '{self.notebook_name}' not found. Available: {available}"
            ) from None

        print("Navigating to logging directory...")
        notebook_log_dir = self._get_or_create_dir(notebook, "Notebook Log")
        user_dir = self._get_or_create_dir(notebook_log_dir, self.user.email)

        timestamp = datetime.now().isoformat(timespec="seconds").replace(":", "-")
        page = user_dir.create(NotebookPage, timestamp)
        entries = page.entries

        print(
            f"Logging to: {self.notebook_name}/Notebook Log/{self.user.email}/{timestamp}"
        )

        # 1. Tags as styled pills
        tags_html = "".join(
            f'<span style="background: #eee; padding: 2px 5px; margin: 2px; border-radius: 3px;">{html.escape(t)}</span>'
            for t in tags
        )
        entries.create_entry("text entry", f"<p><strong>Tags:</strong> {tags_html}</p>")

        # 2. Cell info as HTML
        recent = cell_info.get("recent_cells", [])
        exec_count = cell_info.get("execution_count")
        cells_html = "".join(
            f"<pre style='background:#f5f5f5;padding:6px;margin:4px 0;'>{html.escape(src)}</pre>"
            for src in recent
        )
        cell_html = (
            f"<p><strong>Cell Info</strong> "
            f"(execution count: {exec_count})</p>{cells_html}"
        )
        entries.create_entry("text entry", cell_html)

        # 3. Result as plain text
        entries.create_entry("plain text entry", result)

        # 4. Figures as PNG attachments
        for i, fig_bytes in enumerate(figures, 1):
            attachment = Attachment(
                BytesIO(fig_bytes),
                "image/png",
                f"figure_{i}.png",
                f"Notebook figure {i}",
            )
            entries.create_entry("Attachment", attachment)

        # 5. Tracked files as attachments
        for path in all_files:
            if not os.path.isfile(path):
                print(f"Warning: Tracked file '{path}' is not a valid file.")
                continue

            with open(path, "rb") as f:
                content = f.read()
                mime_type = guess_type(path)[0] or "application/octet-stream"
                filename = os.path.basename(path)
                attachment = Attachment(
                    BytesIO(content),
                    mime_type,
                    filename,
                    f"Attached file: {filename}",
                )
                entries.create_entry("Attachment", attachment)

        print("Log complete!")

    def show_ui(self) -> None:
        """Display an ipywidgets form for tagging and saving the current run."""
        try:
            import ipywidgets as widgets
            from IPython.display import display
        except ImportError:
            print(
                "ipywidgets is required for show_ui(). Install it with: pip install ipywidgets"
            )
            return

        tag_input = widgets.Text(
            placeholder="comma-separated tags (e.g. baseline, v1.0)",
            description="Tags:",
            layout=widgets.Layout(width="450px"),
        )
        save_btn = widgets.Button(
            description="Save to LabArchives", button_style="primary"
        )
        status = widgets.Output()

        def on_save(_: widgets.Button) -> None:
            with status:
                tags = [t.strip() for t in tag_input.value.split(",") if t.strip()]
                self.log(
                    tags=tags,
                    cell_info=self._capture_cell_info(),
                    result=self._capture_last_result(),
                    figures=self._capture_figures(),
                )

        save_btn.on_click(on_save)
        display(widgets.VBox([tag_input, save_btn, status]))
