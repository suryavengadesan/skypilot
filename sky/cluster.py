"""
Deploy a cluster that adds and removes nodes from different cloud vendors

The cluster provisioner follows the CRUD design pattern and utilizes k8s
"""

class Cluster:
	def __init__(self, name): 
		self.name = name

	def create_cluster(self):
		self.setup_kubeadm(self)
		self.initialize_control_plane(self)
		self.authenticate_kubectl(self)
	
	def delete_cluster(self): 
		return 
	
	def setup_kubeadm(self): 
		return 

	def initialize_control_plane(self):
		return

	def authenticate_kubectl(self):
		return 


	class Node:
		def __init__(self, name): 
			self.name = name

		def create_node(self):
			return 

		def join_node(self):
			return 
		
		def detach_node(self): 
			return 

		def delete_node(self): 
			return 

	class Job: 
		def __init__(self, name):
			self.name = name 

		def create_pod(self): 
			return 
		
		def delete_pod(self): 
			return