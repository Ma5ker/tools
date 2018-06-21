def getTargetinArray(array,n):
    '''
	得到一个array中所有值为n的元素的个数
	'''
	swp = array==n
	result = array[swp]
	return result.size