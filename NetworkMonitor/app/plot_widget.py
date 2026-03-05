# NetworkMonitor/app/plot_widget.py
from __future__ import annotations

from collections import deque

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


class PlotWidget(QWidget):
    """
    Два графика:
    - PPS_eff (реальная оценка пакетов/сек)
    - anomaly rate (anom/seen)
    """
    def __init__(self, title: str, max_points: int = 120, parent=None):
        super().__init__(parent)
        self.max_points = max_points
        self.x = deque(maxlen=max_points)
        self.pps = deque(maxlen=max_points)
        self.anom = deque(maxlen=max_points)
        self.t = 0

        layout = QVBoxLayout(self)

        self.title_lbl = QLabel(title)
        layout.addWidget(self.title_lbl)

        # --- Matplotlib Figure/Canvas ---
        self.fig = Figure()
        self.canvas = FigureCanvas(self.fig)
        layout.addWidget(self.canvas)

        # 2 subplots
        self.ax1 = self.fig.add_subplot(2, 1, 1)
        self.ax2 = self.fig.add_subplot(2, 1, 2)

        # lines
        self.line1, = self.ax1.plot([], [], linewidth=2.0)
        self.line2, = self.ax2.plot([], [], linewidth=2.0)

        # labels
        self.ax1.set_ylabel("PPS_eff")
        self.ax2.set_ylabel("Anom rate")
        self.ax2.set_xlabel("time")

        # apply dark theme
        self._apply_dark_theme()
        self.fig.tight_layout()

    def _apply_dark_theme(self):
        # Палитра примерно как в твоём QSS
        bg_main = "#0f111a"
        bg_axes = "#161925"
        fg_text = "#a6adc8"
        grid_c = "#2a2f45"
        spine_c = "#1e2233"

        # фон фигуры и осей
        self.fig.patch.set_facecolor(bg_main)
        self.ax1.set_facecolor(bg_axes)
        self.ax2.set_facecolor(bg_axes)

        # подписи/тики
        for ax in (self.ax1, self.ax2):
            ax.tick_params(colors=fg_text, labelsize=9)
            ax.xaxis.label.set_color(fg_text)
            ax.yaxis.label.set_color(fg_text)

            # рамки
            for spine in ax.spines.values():
                spine.set_color(spine_c)

            # сетка
            ax.grid(True, alpha=0.35, linestyle="-")
            # matplotlib сам выберет цвет по умолчанию, но сетке зададим явно:
            for gl in ax.get_xgridlines() + ax.get_ygridlines():
                gl.set_color(grid_c)

        # если захотишь легенду в будущем:
        # leg = ax.legend(...)
        # leg.get_frame().set_facecolor(bg_axes); leg.get_frame().set_edgecolor(spine_c)

    def push(self, pps_eff: float, anom_rate: float):
        self.t += 1
        self.x.append(self.t)
        self.pps.append(float(pps_eff))
        self.anom.append(float(anom_rate))

        self.line1.set_data(self.x, self.pps)
        self.line2.set_data(self.x, self.anom)

        # авто-масштаб + небольшой padding, чтобы не “липло” к краям
        self.ax1.relim()
        self.ax1.autoscale_view()
        self.ax1.margins(x=0.02, y=0.10)

        self.ax2.relim()
        self.ax2.autoscale_view()
        self.ax2.margins(x=0.02, y=0.10)

        self.canvas.draw_idle()