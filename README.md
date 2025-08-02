# Detecting-malicious-and-benign-traffic-using models trained on IoT-23 dataset
the objective of this project is to train models using machine learnine and deep learning classifiers on IOT-23 dataset obtained from the link: https://www.stratosphereips.org/datasets-iot23 and we downloaded the labeled format because it contains the labels of the traffic
the following are explanations of what we did in order:
## 1 Extracting Datasets
Actually the IOT-23 is not a ready dataset to train and use, indeed there are multiple files in conn.log.labeled format which are labeled traffics but not ready to train models, so the first steep is to download these conn.log.labeled files and extract clear datasets from it in a .csv format, we did not choose all the files because og their very big size which leads to overwheming the models when training, so we chose  the following captures:
CTU-IoT-Malware-Capture-1-1, CTU-IoT-Malware-Capture-3-1, CTU-IoT-Malware-Capture-4-1, CTU-IoT-Malware-Capture-5-1, CTU-IoT-Malware-Capture-7-1, CTU-IoT-Malware-Capture-8-1, CTU-IoT-Malware-Capture-9-1, CTU-IoT-Malware-Capture-20-1, CTU-IoT-Malware-Capture-21-1, CTU-IoT-Malware-Capture-34-1, CTU-IoT-Malware-Capture-35-1, CTU-part of IoT-Malware-Capture-36-1, CTU-IoT-Malware-Capture-42-1, CTU-IoT-Malware-Capture-44-1, CTU-IoT-Malware-Capture-49-1, CTU-IoT-Malware-Capture-60-1
and in the Extracting datasets folder we read the conn.log.labeled files and exrtact datasets from them to .csv format which is good for training.

