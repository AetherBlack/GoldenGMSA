GoldenGMSA -k -use-ldaps -port 636 gmsainfo $DOMAIN/$USER:$PASSWORD@$KDC
GoldenGMSA kdsinfo $DOMAIN/$USER:$PASSWORD
GoldenGMSA gmsainfo $DOMAIN/$USER:$PASSWORD
