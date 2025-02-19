import pandas as pd
import ast
import re
import pickle
import logging
import sys
import os
sys.path.append("utils")

import sqlite_utils
import explore_cwe


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

langs = ["PHP", "C", "JavaScript", "Python", "Java", "TypeScript", "C++", "Go", "Ruby"]
remove_cwe = ['NVD-CWE-noinfo', 'NVD-CWE-Other']
chosen_cwes = ['CWE-20', 'CWE-287', 'CWE-400', 'CWE-668', 'CWE-74']

conn = sqlite_utils.create_connection('/home/keisukek/code/llm-code-vuln/dataset/CVEfixes_v1.0.8/Data/DB.db')


def pre_processing(df):
	# keep only the specified programming languages
	df = df[df['programming_language'].isin(langs)]

	# code diff: both add & del should exist
	df['diff_added'] = df.apply(lambda row: ast.literal_eval(row.diff_parsed)['added'], axis=1)
	df['diff_deleted'] = df.apply(lambda row: ast.literal_eval(row.diff_parsed)['deleted'], axis=1)
	df = df[df['diff_added'].apply(bool) & df['diff_deleted'].apply(bool)]
	df = df.reset_index(drop=True)
	df = df.drop(columns=['diff_parsed'])

	# cve description type str -> arr
	def parse_py_literal(text):
		if not isinstance(text, str):
			return text
		try:
			return ast.literal_eval(text)
		except (SyntaxError, ValueError):
			return None

	df['cve_description'] = df['cve_description'].apply(parse_py_literal)

	# code before and after
	df = df[df['vuln_code'].notna()]
	df = df[df['vuln_code'] != 'None']
	df = df[df['non_vuln_code'].notna()]
	df = df[df['non_vuln_code'] != 'None']

	# remove rows where number of lines in the code is below 30
	for col in ['vuln_code', 'non_vuln_code']:
		df[f'{col}_num_lines'] = df[col].apply(
			lambda x: x.count('\n') + 1 if isinstance(x, str) else 0
		)
		df = df[df[f'{col}_num_lines'] >= 30]

	# remove empty list in diff_deleted
	df = df[df['diff_deleted'].apply(lambda x: isinstance(x, list) and len(x) > 0)]

	# token_count should be num
	df['token_count'] = df['token_count'].apply(parse_py_literal)
	df = df.dropna(subset=['token_count'])
	df['token_count'] = pd.to_numeric(df['token_count'])

	# drop the other CWEs
	df = df[~df["cwe_id"].isin(remove_cwe)]

	# Add Cluss column (Parent CWE)
	cwe_uniques = df['cwe_id'].unique()
	for cwe in cwe_uniques:
		parents = explore_cwe.find_parents_dict(cwe.split('-')[1])
		if parents is None or len(parents['Class']) == 0 : continue
		df.loc[df['cwe_id'] == cwe, 'class'] = parents['Class'][-1]

	df = df.dropna()

	return df

def pick_samples(df):
	sample_size = 10
	vuln_selected = []
	non_vuln_selected = []

	for lang in langs:
			# Vuln samples
			for cwe in chosen_cwes:
					filtered = df[
							(df['programming_language'] == lang) &
							(df['class'] == cwe) &
							(df['token_count'] <= 15000)
					]
					total_available = len(filtered)
					count = 0

					if len(filtered) == 0:
							logger.info('! %s %s No samples available', lang, cwe)
							samples = None  # Indicate there's no data
					elif len(filtered) < sample_size:
							logger.info('- %s %s %d Not enough samples', lang, cwe, len(filtered))
							samples = filtered  # Use all available samples
							count = len(filtered)
					else:
							logger.info('+ %s %s %d', lang, cwe, len(filtered))
							samples = filtered.sample(n=sample_size, random_state=123)
							count = len(samples)

					if samples is not None:
							df = df.drop(samples.index)
							vuln_selected.append(samples)

					percentage_used = (count / total_available) * 100 if total_available > 0 else 0
					logger.info('%s:%s: %d/%d (%.2f%%)', lang, cwe, count, total_available, percentage_used)
			
			# Non-vuln samples
			filtered = df[
							(df['programming_language'] == lang) &
							(df['token_count'] <= 15000)
			]
			samples = filtered.sample(n=sample_size, random_state=123)
			non_vuln_selected.append(samples)
			df = df.drop(samples.index)

	# Combine all selected samples into one DataFrame
	final_vuln_samples = pd.concat(vuln_selected, ignore_index=True) if vuln_selected else pd.DataFrame()
	final_non_vuln_samples = pd.concat(non_vuln_selected, ignore_index=True) if non_vuln_selected else pd.DataFrame()

	# Display final sampled DataFrame
	logger.info('final vuln sample size: %d', len(final_vuln_samples))
	logger.info('final non-vulns sample size: %d', len(final_non_vuln_samples))

	return final_vuln_samples, final_non_vuln_samples, df

def main():
		query = f"""
					SELECT
				file_change.file_change_id,
				file_change.programming_language,
				cwe.cwe_id,
				cwe.cwe_name,
				file_change.code_after AS non_vuln_code,
				file_change.code_before AS vuln_code,
				cwe.description AS cwe_description,
				file_change.diff_parsed,
				cve.description AS cve_description,
				file_change.token_count
		FROM file_change
				INNER JOIN fixes
						ON file_change.hash = fixes.hash
				INNER JOIN cve
						ON fixes.cve_id = cve.cve_id
				INNER JOIN cwe_classification
						ON cve.cve_id = cwe_classification.cve_id
				INNER JOIN cwe
						ON cwe_classification.cwe_id = cwe.cwe_id
		WHERE
				file_change.programming_language IS NOT NULL
				AND cwe.cwe_id IS NOT NULL
				AND cwe.cwe_name IS NOT NULL
				AND file_change.code_before IS NOT NULL
				AND cwe.description IS NOT NULL
				AND file_change.diff_parsed IS NOT NULL
				AND cve.description IS NOT NULL
				AND file_change.token_count IS NOT NULL;
			"""
		logger.info('Executing SQL query to fetch data')
		df = pd.read_sql(query, con=conn)
		logger.info('Data fetched successfully, starting preprocessing')
		df = pre_processing(df)
		logger.info('Preprocessing completed, starting sample selection')
		vuln, non_vuln, df = pick_samples(df)
		logger.info('Sample selection completed, saving data to pickle files')

		os.makedirs('./dataset/test_pickles', exist_ok=True)
		for f_name, data in zip(['test_vuln', 'test_non_vuln', 'df'], [vuln, non_vuln, df]):
			with open(f'./dataset/test_pickles/{f_name}.pkl', 'wb') as f:
				pickle.dump(data, f)
				logger.info('Data saved to %s.pkl', f_name)


if __name__ == '__main__':
	main()
