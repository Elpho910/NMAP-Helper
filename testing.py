import pandas as pd

df = pd.DataFrame(columns=['A', 'B', 'C'])

new_row = {'A': 1, 'B': 2, 'C': 3}

df = df._append(new_row, ignore_index=True)

print(df)
