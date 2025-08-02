# Detecting-malicious-and-benign-traffic-using models trained on IoT-23 dataset
the objective of this project is to train models using machine learnine and deep learning classifiers on IOT-23 dataset obtained from the link: https://www.stratosphereips.org/datasets-iot23 and we downloaded the labeled format because it contains the labels of the traffic
the following are explanations of what we did in order:
## 1 Extracting Datasets
Actually the IOT-23 is not a ready dataset to train and use, indeed there are multiple files in conn.log.labeled format which are labeled traffics but not ready to train models, so the first steep is to download these conn.log.labeled files and extract clear datasets from it in a .csv format, we did not choose all the files because og their very big size which leads to overwheming the models when training, so we chose  the following captures:
CTU-IoT-Malware-Capture-1-1, CTU-IoT-Malware-Capture-3-1, CTU-IoT-Malware-Capture-4-1, CTU-IoT-Malware-Capture-5-1, CTU-IoT-Malware-Capture-7-1, CTU-IoT-Malware-Capture-8-1, CTU-IoT-Malware-Capture-9-1, CTU-IoT-Malware-Capture-20-1, CTU-IoT-Malware-Capture-21-1, CTU-IoT-Malware-Capture-34-1, CTU-IoT-Malware-Capture-35-1, CTU-part of IoT-Malware-Capture-36-1, CTU-IoT-Malware-Capture-42-1, CTU-IoT-Malware-Capture-44-1, CTU-IoT-Malware-Capture-49-1, CTU-IoT-Malware-Capture-60-1
and in the Extracting datasets folder we read the conn.log.labeled files and exrtact datasets from them to .csv format which is good for training.

## 2 Cleaning Datasets
After we extract the dataset, now we need to clean it and drop unnecessary features and handle the missing values and encodeing the labels and the features
so the most important thing is that we transformed the problem to binary classification: '0' for Benign, and '1' for Malicious 
we dropped the rows that have nan values in their Labels (ie. we don't know the label of this row so dropping it is necessary)
we drop the unnecessary features and misleading features:{
'Unnamed: 0': which counts the roes in the dataset,
'ts':TimeStamp,
'uid': Unique identifier for the connection,
'local_orig': local_originator and we drop it because it is an empty column, 
'local_resp': local_response and we drop it because it is an empty column,
'id.orig_h': the ip address of the originator host and it is defferentiable,
'id.resp_h':the ip address of the responder host and it is defferentiable,
'id.orig_p': the port number of the originator,
'history': it's unnecessary since connection_state feature is there}

and we converted the {'duration', 'orig_bytes', 'resp_bytes'} features to float type because they are numeric features not object features,
and deal with nan values of the {'duration', 'orig_bytes', 'resp_bytes'} features as the following:
when connection_state=o (S0 which means a connection attempt but there is no reply) and there are nan values we fill 0s in their places
and when connection_state!=0 we filled the median of the column in the place of nan values

## 3 Combining datasets
Actually, in the second process we cleaned each dataset alone and produced a cleaned dataset from it, so now in thsi code we combine these all cleaned datasets to a one full dataset named as 'combined_dataset.csv' to use it for training and testing the models

## 4 Training Models
Thif folder contain 4 models trained on the 'combined_daataset,csv' dataset.
for each model there is the code that corresponds to the training and testing the model and the final model after training.
