# Python script for synchronizing Access Policies from source Microtenants to a target Microtenant in Zscaler Private Access (ZPA)

# The class definition requires installation of the Python requests library in the Python installation.
# This can be done using the command:
# pip install requests
# pip install yaml

import argparse
import logging as log
import logging.handlers
from datetime import date
import time
import json
import getpass
import copy
import inspect
from typing import Any,IO
import yaml
import os

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ***** ZPA Tenant Class *****

class ZPATenant:
	'''
		A helper class to issue request to a Zscaler Private Access (ZPA) tenant

		See Zscaler's API docs here: https://help.zscaler.com/zpa/api
	'''

	def __init__(self, customer_id=None, client_id=None, client_secret=None, log=None, ssl_verify=False):

		if log == None:
			raise Exception("Logging subsystem failure")
		else:
			self.log = log

		if client_id == None or client_secret == None:
			raise Exception("Missing client ID or secret")
		else:
			self.client_id = client_id
			self.client_secret = client_secret

		self.class_name = 'ZPATenant'
		self.log.info(f"[{self.class_name}] Initializing")

		try:
			self.customer_id = customer_id
			self.api_fqdn = "config.private.zscaler.com"
			self.api_base_url = "/mgmtconfig"
			self.scim_base_url = "/userconfig/v1"
			self.session = None
			self.ssl_verify = ssl_verify
			self.headers = {
				'Content-Type': 'application/json',
				'Cache-Control': 'no-cache',
				'User-Agent': 'Zscaler Python/REST API Connector'
			}

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

	# ***** Authenticate *****	

	def authenticate (self):

		self.log.info(f"[{self.class_name}] Authenticating")

		try:
			uri = f"https://{self.api_fqdn}/signin"
			headers = {
				"Content-Type": "application/x-www-form-urlencoded"
				}
			payload = {
				'client_id': self.client_id,
				'client_secret': self.client_secret
				}

			self.session = requests.Session()

			requests.packages.urllib3.disable_warnings()
			response = self.session.post(uri, headers=headers, data=payload, verify=self.ssl_verify)
	
			if response.status_code == 200:
				# Check that authentication hasn't responded that the account password is expired
				# Notify of approaching expiration appropriately
				returned_session_info = response.json()
				if "expires_in" in returned_session_info:
					expiration_time = returned_session_info["expires_in"]
					self.expires_in = time.time () + int(expiration_time)
					if expiration_time == 0:
						self.log.exception("[{self.class_name} Password has expired.]")
						raise Exception("Password has expired.")
				if "token_type" in returned_session_info:
					self.token_type = returned_session_info["token_type"]
				else:
					raise Exception("Unexpected authentication result.")

				if "access_token" in returned_session_info:
					self.access_token = returned_session_info["access_token"]
				else:
					raise Exception("Unexpected authentication result.")

				self.headers = {
					"Content-Type": "application/json",
					"Authorization": f"{self.token_type} {self.access_token}"
					}
				self.log.info(f"[{self.class_name}] Authentication successful.")
				return self.session
			else:
				self.log.info(f"[{self.class_name}] Authentication unsuccessful. Response '{response.status_code}'.")
				return None

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

	def logout(self):

		if self.session == None:
			self.log.info(f"[{self.class_name}] Logout occurred before authentication. No action taken.")
			return 			

		self.log.info(f"[{self.class_name}] Logging Out")
		try:
			uri = f"https://{self.api_fqdn}/signout"
			headers = self.headers
			payload = {}

			requests.packages.urllib3.disable_warnings()
			response = self.session.post(uri, headers=self.headers, data=payload, verify=self.ssl_verify)

			if response.status_code == 200:
				self.log.info(f"[{self.class_name}] Log out successful.")
			else:
				self.log.info(f"[{self.class_name}] Unexpected result.")
			return

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

	def get_api_url (self):
		uri = f"https://{self.api_fqdn}{self.api_base_url}"
		return uri

	def get_scim_url (self):
		uri = f"https://{self.api_fqdn}{self.scim_base_url}"
		return uri

	# ***** Helpers *****

	def action_object_type(self, action, object_type, data=None):
		return self.action_path(self, action, object_type, data)

	def action_path(self, action, path, data=None):
		if self.session == None:
			self.authenticate() 

		try:
			url = self.get_api_url() + path

			requests.packages.urllib3.disable_warnings()
			if action.lower() == "get":
				response = self.session.get(url, headers=self.headers, verify=self.ssl_verify)
			elif action.lower() == "delete":
				response = self.session.delete(url, headers=self.headers, verify=self.ssl_verify)
			elif action.lower() == "post":
				response = self.session.post(url, headers=self.headers, json=data, verify=self.ssl_verify)
			elif action.lower() == "put":
				response = self.session.put(url, headers=self.headers, json=data, verify=self.ssl_verify)
			else:
				self.log.error(f"[{self.class_name}] Unknown action in object request: {action}")

			if response.status_code == 200:
				data = response.json()
				return data
			elif response.status_code == 201:
				data = response.json()
				self.log.debug(f"[{self.class_name}] Created. No content returned.")
				return data
			elif response.status_code == 204:
				self.log.debug(f"[{self.class_name}] Successful. No content returned.")
				return response
			elif response.status_code == 400:
				self.log.error(f"[{self.class_name}] Invalid or bad request: {response.text}")
				self.log.info(f"[{self.class_name}] {action} - {path} - {data}")
				return response
			elif response.status_code == 401:
				self.log.debug(f"[{self.class_name}] Session is not authenticated or timed out.")
				return response
			elif response.status_code == 403:
				self.log.debug(f"[{self.class_name}] Invalid permissions or inaccessible service.")
				return response
			elif response.status_code == 404:
				self.log.info(f"[{self.class_name}] Resource does not exist: {path}.")
				return response
			elif response.status_code == 409:
				self.log.debug(f"[{self.class_name}] Resource currently locked. Waiting and trying again.")
				time.sleep(5)
				return self.action_path(action, path, data)
			elif response.status_code == 412:
				self.log.debug(f"[{self.class_name}] Precondition failed. Waiting and trying again.")
				time.sleep(5)
				return self.action_path(action, path, data)
			elif response.status_code == 415:
				self.log.debug(f"[{self.class_name}] Unsupported media type; check request header for proper type.")
				return response
			elif response.status_code == 429:
				self.log.debug(f"[{self.class_name}] Hit quota limit; waiting and recursively resubmitting.")
				time.sleep(5)
				return self.action_path(action, path, data)
			elif response.status_code == 500:
				self.log.debug(f"[{self.class_name}] Unexpected error.")
				return response
			elif response.status_code == 503:
				self.log.debug(f"[{self.class_name}] Service is temporarily unavailable.")
				raise SystemExit("Service not available") from None 
			else:
				self.log.debug(f"[{self.class_name}] Unexpected status code: {response.status_code}.")
				return None

		except Exception as err:
			self.log.exception(f"[{self.class_name}] Exception: {err}")
			self.log.info(f"[{self.class_name}] Unexpected result in object request: {action} - {path}")
			return None

	# ***** Microtenants *****

	def get_microtenants(self, microtenant_id=None):

		try:
			url = f"/v1/admin/customers/{self.customer_id}/microtenants"
			if microtenant_id != None:
				url += f"/{microtenant_id}"
			response = self.action_path("get", url)

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

		if "list" in response:
			return response["list"]
		else:
			return []

	def get_microtenant_id_from_name(self, microtenant_name, microtenant_list=None):
		
		if microtenant_list == None:
			microtenant_list = self.get_microtenants()
		
		for microtenant in microtenant_list:
			if "name" in microtenant:
				if microtenant["name"] == microtenant_name:
					return microtenant["id"]

		return None

	def get_microtenant_name_from_id(self, microtenant_id, microtenant_list=None):
		if microtenant_list == None:
			microtenant_list = self.get_microtenants()

		for microtenant in microtenant_list:
			if "id" in microtenant:
				if microtenant["id"] == microtenant_id:
					return microtenant["name"]

		return None

	def get_microtenant_name_from_condition_in_access_policy(self, access_policy):
		
		app_segment_microtenant_id = None
		if access_policy != None:
			if 'conditions' in access_policy:
				conditions = access_policy['conditions']
				for condition in conditions:
					if 'operands' in condition:
						operands = condition['operands']
						for operand in operands:
							if 'objectType' in operand:
								if 'microtenantId' in operand:
									app_segment_microtenant_id = operand['microtenantId']
									break
		else:
			self.log.debug(f"[self.class_name] Access Policy is None when attempting to get name.")

		app_segment_microtenant_name = None
		if app_segment_microtenant_id != None:
			app_segment_microtenant_name = self.get_microtenant_name_from_id(app_segment_microtenant_id)
	
		return app_segment_microtenant_name	

	# ***** IdPs *****

	def get_all_idps(self):

		try:
			url = f"/v2/admin/customers/{self.customer_id}/idp"
			response = self.action_path("get", url)

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

		if "list" in response:
			return response["list"]
		else:
			return []

	# ***** Application Segments *****

	def get_all_application_segments(self, microtenant_id=None):

		# Deal with paging
		page = 1
		pagesize = 500

		try:
			final_response = []
			keep_paging = True
			url_base = f"/v1/admin/customers/{self.customer_id}/application?"
			if microtenant_id != None:
				url_base += f"microtenantId={microtenant_id}&"
			while keep_paging == True:
				url = url_base + f"page={page}&pagesize={pagesize}"
				response = self.action_path("get", url)
				if "totalPages" in response:
					if int(response["totalPages"]) != page:
						page += 1
					else:
						keep_paging = False
				else:
					raise Exception(f"Unexpected response: {response}")

				if "list" in response:
					final_response.extend(response["list"])

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None
				
		return final_response


	def get_shared_application_segments(self, microtenant_id=None):

		application_segments = self.get_all_application_segments(microtenant_id=microtenant_id)
		#self.log.debug(f"[self.class_name] All Application Segments in Microtenant {microtenant_id}: {application_segments}")

		shared_application_segments = []
		for application_segment in application_segments:
			if "sharedMicrotenantDetails" in application_segment:
				shared_application_segments.append(application_segment)

		return shared_application_segments

	def share_application_segment_to_microtenant(self, application_id, source_microtenant_id, target_microtenant_id):

		try:

			url = f"/v1/admin/customers/{self.customer_id}/application/{application_id}/share?microtenantId={source_microtenant_id}"

			target_microtenant_obj = {"shareToMicrotenants": [target_microtenant_id]}
			response = self.action_path("put", url, target_microtenant_obj)

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

		return response

	def search_application_segments(self, search_term, microtenant_id=None):
		try:

			final_response = []
			response = self.action_path("get", f"/v1/admin/customers/{self.customer_id}/application?microtenantId={microtenant_id}&search={search_term}")

			if "list" in response:
				total_count = len(response["list"])
				if total_count > 0:
					final_response.extend(response["list"])
				else:
					self.log.debug(f"[{self.class_name}] No search results were returned.")
		
			# Bug ET-60362 : totalCount not properly representing returned values
			#if "totalCount" in response:
			#	total_count = int(response["totalCount"])
			#	if total_count > 0:
			#		if "list" in response:
			#			final_response.extend(response["list"])
			#	else:
			#		self.log.debug(f"[{self.class_name}] No search results were returned.")
			#else:
			#	self.log.info(f"[{self.class_name}] Search term '{search_term}' resulted in no returned results.")

			self.log.debug(f"[{self.class_name}] Response: {final_response}")

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

		return final_response

	def get_application_segment(self, application_id, microtenant_id=0):
		response = self.action_path("get", f"/v1/admin/customers/{self.customer_id}/application/{application_id}?microtenantId={microtenant_id}")
		return response


	def update_application_segment_domain_names(self, application_id, domain_names, microtenant_id=0):
		app_segment = self.get_application_segment(application_id)
		
		if "domainNames" in app_segment:
			app_segment["domainNames"] = domain_names

		response = self.action_path("put", f"/v1/admin/customers/{self.customer_id}/application/{application_id}?microtenantId={microtenant_id}", app_segment)
		return response


	# ***** Policy Set ***** #

	def get_policy_set_id(self, policy_type="ACCESS_POLICY", microtenant_id=None):

		url = f"/v1/admin/customers/{self.customer_id}/policySet/policyType/{policy_type}"
		if microtenant_id != None:
			url = url + f"?microtenantId={microtenant_id}"

		try:
			response = self.action_path("get", url)

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

		if "id" in response:
			return response["id"]
		else:
			return None

	# ***** Access Policies ***** #

	def convert_access_policy_v1_to_v2(self, access_policy_v1):

		# Different Object Types in Conditions for version 2 Access Policies
		OBJ_TYPE1 = ['APP', 'APP_GROUP'] # values are grouped
		OBJ_TYPE2 = ['CONSOLE', 'MACHINE_GRP', 'LOCATION', 'BRANCH_CONNECTOR_GROUP', 'EDGE_CONNECTOR_GROUP', 'CLIENT_TYPE'] # entryValues are combined
		OBJ_TYPE3 = ['SAML', 'SCIM', 'SCIM_GRP'] # Independent operands; entryValues are one per operand
		OBJ_TYPE4 = ['POSTURE', 'COUNTRY_CODE', 'TRUSTED_NETWORK', 'PLATFORM', 'RISK_FACTOR_TYPE', 'CHROME_ENTERPRISE'] # Independent operands; values are one per operand

		values_dict = {}
		
		# Aggregate required entries from Access Policy v1 and apply at end
		if 'conditions' in access_policy_v1:
			for condition_v1 in access_policy_v1['conditions']:
				if 'operands' in condition_v1:
					for operand_v1 in condition_v1['operands']:
						if 'objectType' in operand_v1:
							obj_type = operand_v1['objectType']
							if obj_type not in values_dict:
								values_dict[obj_type] = []

							if obj_type in OBJ_TYPE1:
								if 'rhs' in operand_v1:
									values_dict[obj_type].append(operand_v1['rhs'])

							elif obj_type in OBJ_TYPE2:
								if 'rhs' in operand_v1:
									values_dict[obj_type].append(operand_v1['rhs'])
								
							elif obj_type in OBJ_TYPE3:
								if 'rhs' in operand_v1 and 'lhs' in operand_v1:
									values_dict[obj_type].append([operand_v1['lhs'], operand_v1['rhs']])

							elif obj_type in OBJ_TYPE4:
								if 'rhs' in operand_v1 and 'lhs' in operand_v1:
									values_dict[obj_type].append([operand_v1['lhs'], operand_v1['rhs']])
							else:
								pass ### jkraenzle

		access_policy_v2 = {}
		#copied_fields = ["name", "description", "action", "operator", "policySetId", ]
		#copied_fields = ["name", "ruleOrder", "priority", "policyType", "operator", "action", "customMsg", "disabled", "extranetEnabled", "policySetId", "defaultRuleName", "defaultRule", "microtenantId"]
		copied_fields = ["policySetId", "name", "description", "action", "customMsg", "microtenantId"]
		for field in copied_fields:
			if field in access_policy_v1:
				access_policy_v2[field] = access_policy_v1[field]

		conditions_v2 = []

		for obj_type, values in values_dict.items():
			condition_v2 = {}
			
			operands_v2 = []
			if obj_type in OBJ_TYPE1:
				operand_v2['objectType'] = key
				operand_v2['values'] = values
				operands_v2.append(operand_v2)
			if obj_type in OBJ_TYPE2:
				operand_v2 = {}
				operand_v2['objectType'] = key
				operand_v2['entryValues'] = [{'lhs':v[0], 'rhs':v[1]} for v in values]
				operands_v2.append(operand_v2)
			if obj_type in OBJ_TYPE3:
				for value in values:
					operand_v2 = {}
					operand_v2['objectType'] = key
					operand_v2['values'] = value
					operands_v2.append(operand_v2)
			if obj_type in OBJ_TYPE4:
				for values in values:
					operand_v2 = {}
					operand_v2['objectType'] = key
					operand_v2['entryValues'] = [{'lhs':v[0], 'rhs':v[1]} for v in values]
					operand_v2['microtenantId'] = operand_v1['microtenantId']
					operands_v2.append(operand_v2)

			condition_v2['operands'] = operands_v2
			conditions_v2.append(condition_v2)

		access_policy_v2['conditions'] = conditions_v2

		return access_policy_v2

	def compare_access_policy_conditions(self, source_access_policy, target_access_policy):

		if 'conditions' in source_access_policy and 'conditions' in target_access_policy:
			source_conditions = source_access_policy['conditions']
			target_conditions = target_access_policy['conditions']

			if len(source_conditions) != len(target_conditions):
				self.log.debug(f"[self.class_name] Source and target Access Policy have different counts.")
				return 1
			
			# Iterate through all criteria matches, including App Segments, Identity, etc. and try to find target matches
			conditions_left_to_match = copy.deepcopy(source_conditions)
			conditions_removed = 0
			for i, source_condition in enumerate(source_conditions):
				for target_condition in target_conditions:
					if 'operator' in source_condition and 'operator' in target_condition:
						# If 'operator' does not match, move to next condition
						if source_condition['operator'] != target_condition['operator']:
							continue

						# Confirm that all 'operands' match
						if 'operands' in source_condition and 'operands' in target_condition:
							source_condition_operands = source_condition['operands']
							target_condition_operands = target_condition['operands']
							operands_left_to_match = copy.deepcopy(source_condition_operands)
							operands_removed = 0
							if len(source_condition_operands) != len(target_condition_operands):
								continue
							for j, source_condition_operand in enumerate(source_condition_operands):
								for target_condition_operand in target_condition_operands:
									if (source_condition_operand['objectType'] == target_condition_operand['objectType']) \
										and (source_condition_operand['lhs'] == target_condition_operand['lhs']) \
										and (source_condition_operand['rhs'] == target_condition_operand['rhs']):
										if (source_condition_operand['objectType'] == 'APP' and source_condition_operand['name'] == target_condition_operand['name']) \
											or (source_condition_operand['objectType'] == 'SCIM_GROUP' and source_condition_operand['idpName'] == target_condition_operand['idpName']):
											del operands_left_to_match[j - operands_removed]
											operands_removed += 1
											break
										else:
											del operands_left_to_match[j - operands_removed]
											operands_removed += 1
											break

							if len(operands_left_to_match) > 0:
								#self.log.debug(f"[{self.class_name}] Yet to find matching target for {operands_left_to_match}. Iterating ...")
								continue
							else:
								del conditions_left_to_match[i - conditions_removed]
								conditions_removed += 1
								break
						else:
							self.log.debug(f"[{self.class_name}] 'operands' does not exist in Access Policy")
					else:
						self.log.debug(f"[{self.class_name}] 'operator' does not match in source/target Conditions in Access Policy")
				else:
					self.log.debug(f"[{self.class_name}] Missing 'operator' in either source or target Conditions in Access Policy")

			if len(conditions_left_to_match) > 0:
				self.log.debug(f"[{self.class_name}] Unmatched conditions: {conditions_left_to_match}")
				return 1
			else:
				return 2
		else:
			self.log.debug(f"[{self.class_name}] Invalid source Access Policy")
			return 1


	def compare_access_policy(self, source_access_policy, target_access_policy):
		# return 2 for directly matching
		# return 1 for partly matching
		# return 0

		#self.log.debug("Comparing two Policies")
		#self.log.debug(f"Source: {source_access_policy}")
		#self.log.debug(f"Target: {target_access_policy}")

		source_comparison_name = self.get_clean_access_policy_name(source_access_policy)

		if 'name' in target_access_policy and source_comparison_name != None:
			if target_access_policy['name'] == source_comparison_name:
				fields_to_compare = ['operator', 'action']
				for field_to_compare in fields_to_compare:
					if field_to_compare in source_access_policy and field_to_compare in target_access_policy:
						if source_access_policy[field_to_compare] != target_access_policy[field_to_compare]:
							return 1
				return self.compare_access_policy_conditions(source_access_policy, target_access_policy)
		
		return 0

	def get_access_policy(self, policy_set_id, rule_id, microtenant_id=None):

		try:

			
			url = f"/v1/admin/customers/{self.customer_id}/policySet/{policy_set_id}/rule/{rule_id}"
			if microtenant_id != None:
				url += f"?microtenantId={microtenant_id}"

			response = self.action_path("get", url)

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

		return response

	def get_access_policies(self, microtenant_id=None):

		# Deal with paging
		page = 1
		pagesize = 500

		try:
			final_response = []
			keep_paging = True
			url_base = f"/v1/admin/customers/{self.customer_id}/policySet/rules/policyType/ACCESS_POLICY?"
			if microtenant_id != None:
				url_base += f"microtenantId={microtenant_id}&"
			while keep_paging == True:
				url = url_base + f"page={page}&pagesize={pagesize}"
				response = self.action_path("get", url)
				if "totalPages" in response:
					total_page_count = int(response["totalPages"])
					if total_page_count == 0:
						keep_paging = False
					elif total_page_count != page:
						page += 1
					else:
						keep_paging = False
				else:
					raise Exception("Unexpected response")

				if "list" in response:
					final_response.extend(response["list"])

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

		return final_response

	def get_application_segments_in_access_policy(self, access_policy):
	
		application_segments = {}
		if 'conditions' in access_policy:
			conditions = access_policy['conditions']
			for condition in conditions:
				operands = condition['operands']
				for operand in operands:
					if 'objectType' in operand:
						if operand['objectType'] == 'APP':
							application_segments[operand['rhs']] = operand['name']

		return application_segments	

	def force_share_of_application_segments_in_access_policies(self, access_policies, source_microtenant_id, target_microtenant_id):
		# Ensure that all Access Policies have Application Segments being shared

		try:	
			# Get list of currently shared Application Segments in Microtenant
			shared_application_segments = self.get_shared_application_segments(microtenant_id=source_microtenant_id)

			# Get current list of shared segment IDs for a quick object to check
			shared_application_segment_ids = []
			for shared_application_segment in shared_application_segments:
				shared_application_segment_ids.append(shared_application_segment['id'])
	
			access_policies_using_shared_segments = []
			# Find which access policies have shared Application Segments and which need to be updated
			for access_policy in access_policies:
				application_segment_dict = self.get_application_segments_in_access_policy(access_policy)
				self.log.debug(f"[{self.class_name}] Access Policy has Application Segments: {application_segment_dict}")

				for application_segment_id, application_segment_name in application_segment_dict.items():
					if application_segment_id not in shared_application_segment_ids:
						self.log.info(f"[{self.class_name}] Sharing missing Application Segment {application_segment_name} to target Microtenant {target_microtenant_id}.")
						self.share_application_segment_to_microtenant(application_segment_id, source_microtenant_id, target_microtenant_id)

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None
			
		return
	
	def get_access_policies_from_source_microtenants(self, microtenant_id=None):

		# Get all Access Policies from source tenant
		access_policies = self.get_access_policies(microtenant_id=microtenant_id)

		return access_policies

	def clean_access_policy_object(self, object):
		keys_to_pop = ['id', 'modifiedTime', 'creationTime', 'modifiedBy', 'ruleOrder'] 
		
		for key_to_pop in keys_to_pop:
			if key_to_pop in object:
				object.pop(key_to_pop)

		for key, value in object.items():
			if isinstance(value, list):
				for i, item in enumerate(object[key]):
					object[key][i] = self.clean_access_policy_object(item)
	
		return object

	def clean_access_policy(self, access_policy):

		cleaned_access_policy = self.clean_access_policy_object(access_policy)
		
		return cleaned_access_policy

	def add_access_policy(self, new_access_policy, microtenant_id=None):

		try:
			# Replace required settings from target tenant: policySetId, ?
			policy_set_id = self.get_policy_set_id(microtenant_id=microtenant_id) 
			new_access_policy["policySetId"] = policy_set_id

			url = f"/v1/admin/customers/{self.customer_id}/policySet/{policy_set_id}/rule"
			if microtenant_id != None:
				url = url + f"?microtenantId={microtenant_id}"
			response = self.action_path("post", url, new_access_policy)
			return response

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

		return None

	def get_clean_access_policy_name(self, access_policy):

		microtenant_name = self.get_microtenant_name_from_condition_in_access_policy(access_policy)
		return microtenant_name + " - " + access_policy["name"]

	def add_access_policy_for_shared_application_segment(self, new_access_policy, microtenant_id=None, rule_order=1):

		try:
			# Remove existing metadata related to specific tenant instance	
			cleaned_access_policy = self.clean_access_policy(new_access_policy)

			# Replace required settings from target tenant: policySetId, ?
			policy_set_id = self.get_policy_set_id(microtenant_id=microtenant_id) 
			cleaned_access_policy["policySetId"] = policy_set_id
			
			# Update name to ensure there are no duplicate Access Policy names across Microtenants
			cleaned_access_policy["name"] = self.get_clean_access_policy_name(cleaned_access_policy)

			url = f"/v1/admin/customers/{self.customer_id}/policySet/{policy_set_id}/rule"
			if microtenant_id != None:
				url = url + f"?microtenantId={microtenant_id}"
			response = self.action_path("post", url, cleaned_access_policy)

			if response != None:
				self.reorder_access_policy(response, rule_order, microtenant_id=microtenant_id)

			return response

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None
		
		return None

	def update_access_policy(self, access_policy_to_update, rule_id, microtenant_id=None, rule_order=1):

		try:
			# Remove existing metadata related to specific tenant instance
			#cleaned_access_policy = self.convert_access_policy_v1_to_v2(access_policy_to_update)
			cleaned_access_policy = self.clean_access_policy(access_policy_to_update)

			cleaned_access_policy["id"] = rule_id
			policy_set_id = self.get_policy_set_id(microtenant_id=microtenant_id)
			cleaned_access_policy["policySetId"] = policy_set_id

			# Update name to ensure there are no duplicate Access Policy names across Microtenants
			cleaned_access_policy["name"] = self.get_clean_access_policy_name(cleaned_access_policy)

			url = f"/v1/admin/customers/{self.customer_id}/policySet/{policy_set_id}/rule/{rule_id}"
			if microtenant_id != None:
				url = url + f"?microtenantId={microtenant_id}"
			response = self.action_path("put", url, cleaned_access_policy)

			if response != None:
				# Get newly updated rule
				access_policy = self.get_access_policy(policy_set_id, rule_id, microtenant_id=microtenant_id)
				self.reorder_access_policy(access_policy, rule_order, microtenant_id=microtenant_id)

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

		return response

	def reorder_access_policy(self, access_policy, rule_order, microtenant_id=None):
		try:
			policy_set_id = self.get_policy_set_id(microtenant_id=microtenant_id)
			if 'id' in access_policy:
				rule_id = access_policy['id']
			else:
				self.log.debug(f"[{self.class_name}] Access Policy does not contain 'id': {access_policy}")

			url = f"/v1/admin/customers/{self.customer_id}/policySet/{policy_set_id}/rule/{rule_id}/reorder/{rule_order}"
			if microtenant_id != None:
				url = url + f"?microtenantId={microtenant_id}"
			response = self.action_path("put", url)

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

		return response

	def delete_access_policy(self, access_policy_to_delete, microtenant_id=None):

		try:
			policy_set_id = access_policy_to_delete['policySetId']
			rule_id = access_policy_to_delete['id']

			url = f"/v1/admin/customers/{self.customer_id}/policySet/{policy_set_id}/rule/{rule_id}"
			if microtenant_id != None:
				url = url + f"?microtenantId={microtenant_id}"
			response = self.action_path("delete", url)
			return response

		except requests.exception.RequestException as e:
			raise SystemExit(e) from None


# ***** Logging *****
LOG_MSG_FORMAT = '[%(asctime)s] %(levelname)s <pid:%(process)d> %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H-%M-%S'
LOG_LEVELS_TXT = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
LOG_LEVELS_ENUM = [log.DEBUG, log.INFO, log.WARNING, log.ERROR, log.CRITICAL]

def log_namer(log_path):
	base_path_with_base_name = log_path.split('.')[0]
	new_path = base_path_with_base_name + '.' + str(date.today()) + '.log'
	return new_path

def init_logs(log_base_name, log_level_txt, logs_dir=None):

	# Function requirements include validating directory path, setting formatting, rotating, and
	# setting log level
	try:
		# Check that supplied logging directory is valid and can be written
		valid_path = False
		if logs_dir != None:
			# Confirm path exists and can be created
			if os.path.exists(logs_dir) == False:
				os.makedirs(logs_dir)
			valid_path = os.access(logs_dir, os.W_OK)
	except Exception as e:
		raise Exception(f"Unexpected error while initializing logs: {e}")

	# If valid path does not exist, try to default to script directory
	if valid_path == False:
		logs_dir = os.path.dirname(os.path.realpath(__file__))
		if os.access(logs_dir, os.W_OK) == False:
			raise Exception(f"Error: Unable to write to backup log directory '{logs_dir}'")

	try:
		log_name = log_namer(log_base_name)
		log_path = os.path.join(logs_dir, log_name)
		log_level = LOG_LEVELS_ENUM[LOG_LEVELS_TXT.index(log_level_txt)]

		root_log = log.getLogger()
		formatter = log.Formatter(fmt=LOG_MSG_FORMAT, datefmt=LOG_DATE_FORMAT)
		handler = logging.handlers.TimedRotatingFileHandler(log_path, when='midnight', interval=1, backupCount=7)
		handler.namer = log_namer
		handler.setFormatter(formatter)
		handler.setLevel(log_level)
		root_log.addHandler(handler)
		root_log.setLevel(log_level)
	except Exception as e:
		raise Exception(f"Unexpected error while configuring log format: {e}")

	return log_path


# ***** Tests *****

class YAMLLoader(yaml.SafeLoader):

	def __init__(self, stream: IO) -> None:

		try:
			self._root = os.path.split(stream.name)[0]
		except AttributeError:
			self._root = os.path.curdir

		super().__init__(stream)

def construct_include(loader: YAMLLoader, node: yaml.Node) -> Any:
	filename = os.path.abspath(os.path.join(loader._root, loader.construct_scalar(node)))
	extension = os.path.splitext(filename)[1].lstrip('.')

	with open(filename, 'r') as f:
		if extension in ('yaml', 'yml'):
			return yaml.load(f, YAMLLoader)

	yaml.add_constructor('!include', construct_include, YAMLLoader)

def yamlread(fn):
	try:
		if fn != None:
			with open(fn) as fh:
				yamlresult = yaml.load(fh, YAMLLoader)
		else:
			yamlresult = None

	except FileNotFoundError:
		yamlresult = None

	return yamlresult

def get_parameters_from_config(filename, keys):
	config_file = yamlread(filename)
	error = False

	for tenant_key in keys:
		if tenant_key not in config_file:
			print(f"[application_segment] Tenant '{tenant_key}' missing in configuration file '{filename}'.") 
			error = True

	if error == True:
		return None
	else:
		return config_file

def get_parameters():

	parser = argparse.ArgumentParser(description="Script to update cloud applications")
	parser.add_argument("--config", required=False)
	parser.add_argument("--ssl_verify", default=False, required=False)
	parser.add_argument("--log_level", default="DEBUG", required=False)
	args = parser.parse_args()

	parameters = {}
	parameters["ssl_verify"] = args.ssl_verify
	parameters["log_level"] = args.log_level

	keys = ["customer_id", "client_id", "client_secret", "target", "skiplist"]
	config_file_parameters = {}
	if args.config != None or args.config != "":
		config_file_parameters = get_parameters_from_config(args.config, keys)

	for key in keys:
		if key in config_file_parameters:
			parameters[key] = config_file_parameters[key]

	return parameters

def pull_tags_from_description(description):

	tags = []
	possible_tags = description.split('\r')
	for possible_tag in possible_tags:
		possible_key_value_pair = possible_tag.split(':')
		if len(possible_key_value_pair) == 2:
			key = possible_key_value_pair[0].strip()
			possible_list_of_values = possible_key_value_pair[1].split(',')
			if len(possible_list_of_values) == 1:
				value = possible_key_value_pair[1].strip()
			else:
				value = possible_list_of_values

			tag = {}
			tag[key] = value
			tags.append(tag)

	if len(tags) > 0:
		return tags
	else:
		return []

def remove_source_microtenant_configurations(access_policies):

	for access_policy in access_policies:
		if 'appConnectorGroups' in access_policy:
			access_policy.pop('appConnectorGroups')
		if 'appServerGroups' in access_policy:
			access_policy.pop('appServerGroups')

	return access_policies

def sync():

	parameters = get_parameters()
	log_path = init_logs("AccessPolicySync", parameters["log_level"])

	##### Authenticate to ZPA tenant #####
	tenant = ZPATenant(customer_id=parameters["customer_id"], 
		client_id=parameters["client_id"], 
		client_secret=parameters["client_secret"],
		log=log, ssl_verify=parameters["ssl_verify"])
	tenant.authenticate()

	##### Get list of Microtenants #####
	microtenants = tenant.get_microtenants()

	##### Pull target Microtenant out of list #####
	target_microtenant = parameters["target"]
	target_microtenant_id = tenant.get_microtenant_id_from_name(target_microtenant)
	if target_microtenant_id == None:
		log.error(f"[Access Policy Sync] Incorrect microtenant name in configuration {target_microtenant}. Exiting ...")
		return

	##### Pull Microtenant to skip out of list #####
	tenants_to_skip = parameters["skiplist"]
	skip_microtenant_ids = []
	for tenant_to_skip in tenants_to_skip:
		skip_microtenant_id = tenant.get_microtenant_id_from_name(tenant_to_skip)
		if skip_microtenant_id != None:
			skip_microtenant_ids.append(skip_microtenant_id)
		else:
			log.error(f"[Access Policy Sync] {tenant_to_skip} microtenant name not found in configuration. Exiting ...")
			return
	
	##### Get existing Access Policies in target tenant #####
	target_access_policies = tenant.get_access_policies(microtenant_id=target_microtenant_id)
	target_access_policy_count = len(target_access_policies)
	log.info(f"[Access Policy Sync] There {'are' if target_access_policy_count != 1 else 'is'} {target_access_policy_count} existing target Microtenant {'policies' if target_access_policy_count != 1 else 'policy'}")
	#log.debug(f"[Access Policy Sync] Target Access Policies: {target_access_policies}")

	##### Get all Access Policies using shared Application Segments in supporting tenants #####
	log.info("[Access Policy Sync] The following Microtenants have valid source policies to be synchronized with target Microtenant")
	source_access_policies = []
	##### For each Microtenant #####
	for microtenant in microtenants:
		##### Skip target and Default microtenants #####
		if "id" in microtenant:
			microtenant_id = microtenant['id']
			if (microtenant_id == target_microtenant_id) or (microtenant_id in skip_microtenant_ids):
				continue
		else:
			log.error(f"[Access Policy Sync] Microtenant missing ID. Exiting ...")
			return

		##### Get all Access Policies in source tenant #####
		microtenant_policies = tenant.get_access_policies_from_source_microtenants(microtenant_id=microtenant_id)
		log.info(f"[Access Policy Sync] {len(microtenant_policies)} valid source policies in Microtenant {microtenant['name']}")

		##### Force Application Segment sharing for these Access Policies #####
		tenant.force_share_of_application_segments_in_access_policies(microtenant_policies, microtenant_id, target_microtenant_id)

		##### Aggregate all source Access Policies #####
		source_access_policies.extend(microtenant_policies)

	source_access_policy_count = len(source_access_policies)
	log.info(f"[Access Policy Sync] There {'are' if source_access_policy_count != 1 else 'is'} {source_access_policy_count} existing valid source {'policies' if source_access_policy_count != 1 else 'policy'} across the source Microtenants")
	#log.debug(f"[Access Policy Sync] Source Access Policies: {source_access_policies}")

	##### Remove local Microtenant configurations from source Access Policies #####
	source_access_policies = remove_source_microtenant_configurations(source_access_policies)

	##### Synchronize Access Policies #####
	new_access_policies = []
	access_policies_to_update = []
	access_policies_with_no_changes = []
	access_policies_left_to_delete = target_access_policies
	access_policy_order = {}
	for i, source_access_policy in enumerate(source_access_policies):
		source_access_policy_found = False
		for target_access_policy in target_access_policies:
			compare_result = tenant.compare_access_policy(source_access_policy, target_access_policy)
			if compare_result == 2:
				log.debug(f"[Access Policy Sync] Found a matching Access Policy: {source_access_policy['name']}")
				source_access_policy_found = True
				access_policies_with_no_changes.append(target_access_policy)
				access_policies_left_to_delete.remove(target_access_policy)
				access_policy_order[i + 1] = {"policy":target_access_policy, "status":"no_change"}
				break
			if compare_result == 1:
				log.debug(f"[Access Policy Sync] Found matching Access Policy {source_access_policy['name']} but it needs to be updated")
				source_access_policy_found = True
				update_policy_dict = {"rule_resource":source_access_policy, "rule_id":target_access_policy['id']} 
				access_policies_to_update.append(update_policy_dict)
				access_policies_left_to_delete.remove(target_access_policy)
				access_policy_order[i + 1] = {"policy":update_policy_dict, "status":"update"}
				break
			if compare_result == 0:
				pass

		if source_access_policy_found == False:
			new_access_policies.append(source_access_policy)
			access_policy_order[i + 1] = {"policy":source_access_policy, "status":"new"}


	log.info(f"[Access Policy Sync] There are {len(access_policies_with_no_changes)} policies that need no changes, although order may be updated")
	log.info(f"[Access Policy Sync] There are {len(access_policies_to_update)} policies to update")
	log.info(f"[Access Policy Sync] There are {len(new_access_policies)} new access policies to create")
	log.info(f"[Access Policy Sync] There are {len(access_policies_left_to_delete)} policies to remove from target environment")

	##### Add in reverse order #####
	log.info(f"[Access Policy Sync] Beginning changes to target Microtenant")
	total_entries = len(access_policy_order.items())
	counter = 2 if total_entries / 10 == 0 else total_entries / 10
	for i, (order, value) in enumerate(access_policy_order.items()):
		if order % counter == 0:
			log.debug(f"[Access Policy Sync] Processing rule {order} of {total_entries} (counting by {counter})")
		status = value["status"]
		policy = value["policy"]

		if status == "update":
			##### Update existing Access Policies #####
			tenant.update_access_policy(policy["rule_resource"], policy["rule_id"], microtenant_id=target_microtenant_id, rule_order=order)
		elif status == "new":
			##### Create new Access Policies #####
			tenant.add_access_policy_for_shared_application_segment(policy, microtenant_id=target_microtenant_id, rule_order=order)
		elif status == "no_change":
			##### Update Access Policy order #####
			tenant.reorder_access_policy(policy, order, microtenant_id=target_microtenant_id)

	##### Delete old Access Policies #####
	log.info(f"[Access Policy Sync] Deleting rules no longer configured in source Microtenants")
	for access_policy_to_delete in access_policies_left_to_delete:
		tenant.delete_access_policy(access_policy_to_delete, microtenant_id=target_microtenant_id)

	tenant.logout()

	return


def main():
	sync()

if __name__ == "__main__":
	main()
