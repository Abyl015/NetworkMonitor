from __future__ import annotations

from collections import deque

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


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
        bg_main = "#0f111a"
        bg_axes = "#161925"
        fg_text = "#a6adc8"
        grid_c = "#2a2f45"
        spine_c = "#1e2233"

        self.fig.patch.set_facecolor(bg_main)
        self.ax.set_facecolor(bg_axes)

        self.ax.tick_params(colors=fg_text, labelsize=9)
        self.ax.xaxis.label.set_color(fg_text)
        self.ax.yaxis.label.set_color(fg_text)

        for spine in self.ax.spines.values():
            spine.set_color(spine_c)

        self.ax.grid(True, alpha=0.35, linestyle="-")
        for gl in self.ax.get_xgridlines() + self.ax.get_ygridlines():
            gl.set_color(grid_c)

    def push(self, pps_eff: float, anom_rate: float):
        self.t += 1
        self.x.append(self.t)
        self.pps.append(float(pps_eff))

        self.line.set_data(self.x, self.pps)

        self.ax.relim()
        self.ax.autoscale_view()
        self.ax.margins(x=0.02, y=0.10)

        self.canvas.draw_idle()