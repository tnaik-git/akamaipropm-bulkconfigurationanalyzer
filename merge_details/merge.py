import pandas as pd
import os

def merge_excel_sheets_in_folder(folder_path, output_csv="merged_properties.csv"):
    merged_df = pd.DataFrame()

    for filename in os.listdir(folder_path):
        if filename.endswith(".xlsx"):
            file_path = os.path.join(folder_path, filename)
            xls = pd.ExcelFile(file_path)

            for sheet in xls.sheet_names:
                df = pd.read_excel(xls, sheet)
                df["source_account"] = f"{filename} - {sheet}"  # Source identifier
                merged_df = pd.concat([merged_df, df], ignore_index=True)

    if not merged_df.empty:
        merged_df.to_csv(output_csv, index=False)
        print(f"✅ Saved merged CSV to: {output_csv}")
    else:
        print("⚠️ No data found to merge.")

if __name__ == "__main__":
    user_input = input("Do you want to combine all Excel files in a folder into a single CSV? (yes/no): ").strip().lower()

    if user_input in ["yes", "y"]:
        folder_path = input("Enter the folder path containing the Excel files: ").strip()
        if os.path.isdir(folder_path):
            merge_excel_sheets_in_folder(folder_path)
        else:
            print("❌ Invalid folder path. Exiting.")
    else:
        print("❎ Merge skipped.")
