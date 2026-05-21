from __future__ import annotations

from collections import deque

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


def _apply_dark_axes_theme(fig: Figure, ax) -> None:
    bg_main = "#0f111a"
    bg_axes = "#161925"
    fg_text = "#a6adc8"
    grid_c = "#2a2f45"
    spine_c = "#1e2233"

    fig.patch.set_facecolor(bg_main)
    ax.set_facecolor(bg_axes)

    ax.tick_params(colors=fg_text, labelsize=9)
    ax.xaxis.label.set_color(fg_text)
    ax.yaxis.label.set_color(fg_text)
    ax.title.set_color(fg_text)

    for spine in ax.spines.values():
        spine.set_color(spine_c)

    ax.grid(True, alpha=0.35, linestyle="-")
    for gl in ax.get_xgridlines() + ax.get_ygridlines():
        gl.set_color(grid_c)


class PlotWidget(QWidget):
    def __init__(self, title: str, max_points: int = 120, parent=None):
        super().__init__(parent)
        self.max_points = max_points
        self.x = deque(maxlen=max_points)
        self.pps = deque(maxlen=max_points)
        self.t = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.title_lbl = QLabel(title)
        layout.addWidget(self.title_lbl)

        self.fig = Figure()
        self.canvas = FigureCanvas(self.fig)
        layout.addWidget(self.canvas)

        self.ax = self.fig.add_subplot(1, 1, 1)
        self.line, = self.ax.plot([], [], linewidth=2.0)

        self.ax.set_ylabel("PPS_eff")
        self.ax.set_xlabel("time")

        self._apply_dark_theme()
        self.fig.tight_layout()

    def _apply_dark_theme(self):
        _apply_dark_axes_theme(self.fig, self.ax)

    def push(self, pps_eff: float, anom_rate: float):
        self.t += 1
        self.x.append(self.t)
        self.pps.append(float(pps_eff))

        self.line.set_data(self.x, self.pps)

        self.ax.relim()
        self.ax.autoscale_view()
        self.ax.margins(x=0.02, y=0.10)

        self.canvas.draw_idle()


class AnalyticsChartWidget(QWidget):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.title_lbl = QLabel(title)
        layout.addWidget(self.title_lbl)

        self.fig = Figure()
        self.canvas = FigureCanvas(self.fig)
        layout.addWidget(self.canvas)

        self.ax = self.fig.add_subplot(1, 1, 1)
        _apply_dark_axes_theme(self.fig, self.ax)
        self.fig.tight_layout()

    def _reset_axes(self) -> None:
        self.ax.clear()
        _apply_dark_axes_theme(self.fig, self.ax)

    def show_empty(self, text: str = "Нет данных") -> None:
        self._reset_axes()
        self.ax.text(
            0.5,
            0.5,
            text,
            ha="center",
            va="center",
            color="#a6adc8",
            transform=self.ax.transAxes,
        )
        self.ax.set_xticks([])
        self.ax.set_yticks([])
        self.canvas.draw_idle()

    def plot_line(self, labels: list[str], values: list[float], ylabel: str) -> None:
        self._reset_axes()
        if not labels or not values:
            self.show_empty()
            return

        x_values = list(range(len(values)))
        self.ax.plot(x_values, values, marker="o", linewidth=2.0, color="#89b4fa")
        self.ax.set_ylabel(ylabel)
        self.ax.set_xlabel("Сессия")
        self.ax.set_xticks(x_values)
        self.ax.set_xticklabels(labels, rotation=30, ha="right")
        self.ax.margins(x=0.04, y=0.12)
        self.fig.tight_layout()
        self.canvas.draw_idle()

    def plot_bars(self, labels: list[str], values: list[float], ylabel: str) -> None:
        self._reset_axes()
        if not labels or not values:
            self.show_empty()
            return

        colors = ["#89b4fa", "#f9e2af", "#f38ba8", "#a6e3a1", "#cba6f7"]
        self.ax.bar(labels, values, color=colors[:len(labels)])
        self.ax.set_ylabel(ylabel)
        self.ax.tick_params(axis="x", rotation=20)
        self.ax.margins(y=0.15)
        self.fig.tight_layout()
        self.canvas.draw_idle()
