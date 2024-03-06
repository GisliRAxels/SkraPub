Iceland has started to issue ID-cards according to the provisions of reglulation (EU) 2019/1157. The new cards will start to appear on borders in March of 2024.

This is the first travel document in the world issued in portrait format according to a new ICAO specification for TD1 documents, see 
https://www.icao.int/Security/FAL/TRIP/PublishingImages/Pages/Publications/ICAO%20TR%20-%20Additional%20TD1-format.pdf

The document is also the first to a include the new ICAO Datastructure for Barcode (IDB), see 
https://www.icao.int/Security/FAL/TRIP/PublishingImages/Pages/Publications/ICAO%20TR%20-%20ICAO%20Datastructure%20for%20Barcode.pdf

On the front side of the card is a barcode which contains the CAN. 
On the back side there is a larger barcode that contains digitally signed visible information from the card, more specifically a tiny facial image, MRZ and full name using Icelandic letters.

For more information regarding the barcode structure please refer to the Data demonstration and Diagram files in the github.

A general implementation of the code for the barcode generation can be found here in the github aswell as a decoder for it.  Please note the decoder as is is not intended for all types of IDB but is specifically made for IS IDB.
