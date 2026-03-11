#!/usr/bin/env python3
"""
Interface de validation manuelle des alertes ML.
Permet de confirmer ou corriger les labels pour alimenter l'apprentissage continu.
"""

import argparse
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from typing import List, Tuple, Optional

from trainer import ContinuousLearningSystem


class ManualValidationUI:
    """UI locale pour valider les alertes et ajouter du feedback utilisateur."""

    def __init__(self, db_path: str, feedback_threshold: int = 10):
        self.db_path = Path(db_path)
        self.system = ContinuousLearningSystem(
            db_path=str(self.db_path),
            feedback_threshold=feedback_threshold,
        )

        self.root = tk.Tk()
        self.root.title("Celestis IA - Validation manuelle")
        self.root.geometry("1300x760")

        self.only_unvalidated = tk.BooleanVar(value=True)
        self.limit_var = tk.StringVar(value="200")
        self.confidence_var = tk.StringVar(value="1.0")
        self.model_type_var = tk.StringVar(value="random_forest")
        self.model_name_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Pret")

        self.selected_row: Optional[Tuple] = None

        self._build_layout()
        self._refresh_table()
        self._refresh_status()

    def _build_layout(self) -> None:
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill=tk.X)

        ttk.Checkbutton(
            top_frame,
            text="Afficher seulement les alertes non validees",
            variable=self.only_unvalidated,
            command=self._refresh_table,
        ).pack(side=tk.LEFT)

        ttk.Label(top_frame, text="Limite:").pack(side=tk.LEFT, padx=(15, 5))
        limit_entry = ttk.Entry(top_frame, textvariable=self.limit_var, width=8)
        limit_entry.pack(side=tk.LEFT)

        ttk.Label(top_frame, text="Confiance:").pack(side=tk.LEFT, padx=(15, 5))
        conf_entry = ttk.Entry(top_frame, textvariable=self.confidence_var, width=8)
        conf_entry.pack(side=tk.LEFT)

        ttk.Button(top_frame, text="Rafraichir", command=self._refresh_table).pack(side=tk.LEFT, padx=10)

        self.pending_label = ttk.Label(top_frame, text="Feedback en attente: 0")
        self.pending_label.pack(side=tk.RIGHT)

        columns = (
            "alert_id",
            "pcap_file_id",
            "packet_number",
            "severity",
            "rule_name",
            "src_ip",
            "dst_ip",
            "protocol",
            "feedback",
        )

        table_frame = ttk.Frame(self.root, padding=(10, 0, 10, 0))
        table_frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        for col in columns:
            self.tree.heading(col, text=col)

        self.tree.column("alert_id", width=80, anchor=tk.CENTER)
        self.tree.column("pcap_file_id", width=90, anchor=tk.CENTER)
        self.tree.column("packet_number", width=110, anchor=tk.CENTER)
        self.tree.column("severity", width=90, anchor=tk.CENTER)
        self.tree.column("rule_name", width=260)
        self.tree.column("src_ip", width=140)
        self.tree.column("dst_ip", width=140)
        self.tree.column("protocol", width=90, anchor=tk.CENTER)
        self.tree.column("feedback", width=130, anchor=tk.CENTER)

        y_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        x_scroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        self.tree.tag_configure("label_1", background="#ffcccc", foreground="#8b0000")
        self.tree.tag_configure("label_0", background="#ccffcc", foreground="#005000")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        detail_frame = ttk.LabelFrame(self.root, text="Details de l'alerte", padding=10)
        detail_frame.pack(fill=tk.BOTH, padx=10, pady=10)

        self.details_text = tk.Text(detail_frame, height=8, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)

        action_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        action_frame.pack(fill=tk.X)

        ttk.Button(
            action_frame,
            text="Confirmer menace (label=1)",
            command=lambda: self._submit_feedback(1),
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            action_frame,
            text="Marquer normal (label=0)",
            command=lambda: self._submit_feedback(0),
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(action_frame, text="Model type:").pack(side=tk.LEFT, padx=(20, 5))
        model_type_combo = ttk.Combobox(
            action_frame,
            textvariable=self.model_type_var,
            width=16,
            state="readonly",
            values=["random_forest", "anomaly"],
        )
        model_type_combo.pack(side=tk.LEFT)

        ttk.Label(action_frame, text="Model name (optionnel):").pack(side=tk.LEFT, padx=(10, 5))
        ttk.Entry(action_frame, textvariable=self.model_name_var, width=22).pack(side=tk.LEFT)

        ttk.Button(
            action_frame,
            text="Re-entrainer maintenant",
            command=self._retrain_now,
        ).pack(side=tk.RIGHT)

        status_bar = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=10, pady=(0, 10))

    def _fetch_rows(self) -> List[Tuple]:
        limit_raw = self.limit_var.get().strip()
        try:
            limit = max(1, int(limit_raw))
        except ValueError:
            limit = 200
            self.limit_var.set("200")

        where_sql = ""
        if self.only_unvalidated.get():
            where_sql = "WHERE fb.id IS NULL"

        query = f"""
            SELECT
                ta.id,
                ta.pcap_file_id,
                ta.packet_number,
                ta.severity,
                ta.rule_name,
                COALESCE(ta.src_ip, ''),
                COALESCE(ta.dst_ip, ''),
                COALESCE(ta.protocol, ''),
                ta.description,
                ta.timestamp,
                p.filename,
                fb.actual_label
            FROM threat_alerts ta
            LEFT JOIN pcap_files p ON p.id = ta.pcap_file_id
            LEFT JOIN ml_feedback fb
                ON fb.pcap_file_id = ta.pcap_file_id
               AND fb.packet_number = ta.packet_number
            {where_sql}
            ORDER BY ta.id DESC
            LIMIT ?
        """

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            return cursor.fetchall()

    def _refresh_table(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            rows = self._fetch_rows()
        except Exception as exc:
            messagebox.showerror("Erreur", f"Impossible de charger les alertes: {exc}")
            return

        for row in rows:
            if row[11] is None:
                feedback_text = "non valide"
                row_tag = "unvalidated"
            elif int(row[11]) == 1:
                feedback_text = "label=1"
                row_tag = "label_1"
            else:
                feedback_text = "label=0"
                row_tag = "label_0"

            self.tree.insert(
                "",
                tk.END,
                values=(
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                    row[6],
                    row[7],
                    feedback_text,
                ),
                tags=(row_tag,),
            )

        self.status_var.set(f"{len(rows)} alerte(s) chargee(s)")
        self._refresh_status()

    def _on_select(self, _event=None) -> None:
        selected_items = self.tree.selection()
        if not selected_items:
            self.selected_row = None
            return

        item_id = selected_items[0]
        values = self.tree.item(item_id, "values")
        if not values:
            self.selected_row = None
            return

        alert_id = int(values[0])
        full_row = self._fetch_row_by_alert_id(alert_id)
        self.selected_row = full_row

        if full_row is None:
            return

        details = [
            f"Alert ID      : {full_row[0]}",
            f"PCAP ID       : {full_row[1]} ({full_row[10]})",
            f"Packet number : {full_row[2]}",
            f"Severity      : {full_row[3]}",
            f"Rule          : {full_row[4]}",
            f"Source        : {full_row[5]}",
            f"Destination   : {full_row[6]}",
            f"Protocol      : {full_row[7]}",
            f"Timestamp     : {full_row[9]}",
            "",
            "Description:",
            str(full_row[8] or ""),
        ]

        self.details_text.delete("1.0", tk.END)
        self.details_text.insert(tk.END, "\n".join(details))

    def _fetch_row_by_alert_id(self, alert_id: int) -> Optional[Tuple]:
        query = """
            SELECT
                ta.id,
                ta.pcap_file_id,
                ta.packet_number,
                ta.severity,
                ta.rule_name,
                COALESCE(ta.src_ip, ''),
                COALESCE(ta.dst_ip, ''),
                COALESCE(ta.protocol, ''),
                ta.description,
                ta.timestamp,
                COALESCE(p.filename, '')
            FROM threat_alerts ta
            LEFT JOIN pcap_files p ON p.id = ta.pcap_file_id
            WHERE ta.id = ?
            LIMIT 1
        """

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, (alert_id,))
            return cursor.fetchone()

    def _parse_confidence(self) -> Optional[float]:
        raw_value = self.confidence_var.get().strip()
        try:
            confidence = float(raw_value)
        except ValueError:
            messagebox.showwarning("Confiance invalide", "La confiance doit etre un nombre entre 0 et 1.")
            return None

        if confidence < 0.0 or confidence > 1.0:
            messagebox.showwarning("Confiance invalide", "La confiance doit etre comprise entre 0 et 1.")
            return None

        return confidence

    def _submit_feedback(self, actual_label: int) -> None:
        if self.selected_row is None:
            messagebox.showinfo("Selection requise", "Selectionnez une alerte dans la liste.")
            return

        confidence = self._parse_confidence()
        if confidence is None:
            return

        pcap_file_id = int(self.selected_row[1])
        packet_number = int(self.selected_row[2])

        predicted_label = 1  # threat_alerts correspond a une prediction de menace

        try:
            self.system.add_feedback(
                pcap_file_id=pcap_file_id,
                packet_number=packet_number,
                predicted_label=predicted_label,
                actual_label=actual_label,
                confidence=confidence,
            )
            self.status_var.set(
                f"Feedback enregistre: alert={self.selected_row[0]}, packet={packet_number}, label={actual_label}"
            )
            self._refresh_table()
        except Exception as exc:
            messagebox.showerror("Erreur", f"Impossible d'enregistrer le feedback: {exc}")

    def _retrain_now(self) -> None:
        model_type = self.model_type_var.get().strip() or "random_forest"
        model_name = self.model_name_var.get().strip() or None

        if not self.system.is_retrain_recommended():
            confirm = messagebox.askyesno(
                "Seuil non atteint",
                "Le seuil de feedback n'est pas atteint. Continuer le re-entrainement quand meme ?",
            )
            if not confirm:
                return

        try:
            self.status_var.set("Re-entrainement en cours...")
            self.root.update_idletasks()

            _model, metrics = self.system.retrain_with_feedback(
                model_name=model_name,
                model_type=model_type,
            )

            val_acc = float(metrics.get("val_accuracy", 0.0))
            self.status_var.set(f"Re-entrainement termine. val_accuracy={val_acc:.4f}")
            self._refresh_status()
            messagebox.showinfo(
                "Re-entrainement termine",
                f"Modele mis a jour avec succes.\nValidation accuracy: {val_acc:.4f}",
            )
        except Exception as exc:
            self.status_var.set("Erreur de re-entrainement")
            messagebox.showerror("Erreur", f"Le re-entrainement a echoue: {exc}")

    def _refresh_status(self) -> None:
        pending = self.system.get_unused_feedback_count()
        threshold = self.system.feedback_threshold
        self.pending_label.config(text=f"Feedback en attente: {pending}/{threshold}")

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Interface locale de validation manuelle des alertes"
    )
    parser.add_argument(
        "--db",
        default="../zeus/pcap_database.db",
        help="Chemin vers la base de donnees SQLite",
    )
    parser.add_argument(
        "--feedback-threshold",
        type=int,
        default=10,
        help="Nombre de feedbacks requis avant recommandation de re-entrainement",
    )

    args = parser.parse_args()

    ui = ManualValidationUI(
        db_path=args.db,
        feedback_threshold=max(1, int(args.feedback_threshold)),
    )
    ui.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
