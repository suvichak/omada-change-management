"""omadawrite — change control box for the Omada controller.

AI submits a proposal (a list of Omada internal-API requests). A human logs in
with an Omada admin account, reviews and approves it. The box snapshots the
controller VM through the Proxmox API, runs the requests, then watches the
internet. If the internet stays down it rolls the VM back to the snapshot.
There is no AI inside the box.
"""
